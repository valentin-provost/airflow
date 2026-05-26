from airflow.sdk import DAG
from airflow.providers.standard.operators.empty import EmptyOperator
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
import pandas as pd
from io import StringIO
import ipaddress
import json

def process_filter_ipv4(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids='extract_dbip')
    df = pd.read_csv(StringIO(data), names=['ip_start_range', 'ip_end_range', 'country_code'])
    # Filtrer uniquement les IPv4 valides
    df_filtered = df[df['ip_start_range'].str.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', na=False)]
    print(f'Before filter: {len(df)}, After filter: {len(df_filtered)}')
    return df_filtered.to_json(orient='records')

def process_filter_remove_col(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids='extract_pub_log')
    df = pd.read_csv(StringIO(data))
    if 'Destination_IP' in df.columns:
        df_filtered = df.drop(columns=['Destination_IP'])
    else:
        df_filtered = df
    return df_filtered.to_json(orient='records')

def process_convert_ipv4(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids='filter_ipv4')
    df = pd.read_json(StringIO(data), orient='records')
    
    df['ip_start_int'] = df['ip_start_range'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    df['ip_end_int'] = df['ip_end_range'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    return df.to_json(orient='records')

def process_convert_ipv4_pub(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids='filter_remove_col')
    df = pd.read_json(StringIO(data), orient='records')
    
    df['Source_IP_int'] = df['Source_IP'].apply(lambda ip: int(ipaddress.IPv4Address(ip)) if pd.notnull(ip) else 0)
    return df.to_json(orient='records')

def process_map_ip_country(task_instance):
    db_data = task_instance.xcom_pull(key='return_value', task_ids='convert_into_ipv4')
    log_data = task_instance.xcom_pull(key='return_value', task_ids='convert_into_ipv4_pub')
    
    df_db = pd.read_json(StringIO(db_data), orient='records')
    df_log = pd.read_json(StringIO(log_data), orient='records')
    
    def get_country(ip_int):
        match = df_db[(df_db['ip_start_int'] <= ip_int) & (df_db['ip_end_int'] >= ip_int)]
        if not match.empty:
            return match.iloc[0]['country_code']
        return "Unknown"
    
    df_log['Country_Code'] = df_log['Source_IP_int'].apply(get_country)
    return df_log.to_json(orient='records')

def process_load(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids='map_ip_country')
    df = pd.read_json(StringIO(data), orient='records')
    
    hook = PostgresHook(postgres_conn_id='postgres_dwh')
    engine = hook.get_sqlalchemy_engine()
    
    df.to_sql('intrusion_logs_mapped', engine, if_exists='append', index=False)
    print(f"{len(df)} lignes insérées avec succès.")

with DAG(dag_id='intrusion', schedule=None, catchup=False):
    extract_dbip = HttpOperator(
        task_id='extract_dbip',
        method='GET',
        endpoint='dbip-country-lite-2026-01.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    
    extract_pub_log = HttpOperator(
        task_id='extract_pub_log',
        method='GET',
        endpoint='public_network_logs.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    
    filter_ipv4 = PythonOperator(
        task_id='filter_ipv4',
        python_callable=process_filter_ipv4
    )
    
    convert_into_ipv4 = PythonOperator(
        task_id='convert_into_ipv4',
        python_callable=process_convert_ipv4
    )
    
    filter_remove_col = PythonOperator(
        task_id='filter_remove_col',
        python_callable=process_filter_remove_col
    )
    
    convert_into_ipv4_pub = PythonOperator(
        task_id='convert_into_ipv4_pub',
        python_callable=process_convert_ipv4_pub
    )
    
    map_ip_country = PythonOperator(
        task_id='map_ip_country',
        python_callable=process_map_ip_country
    )
    
    load = PythonOperator(
        task_id='load',
        python_callable=process_load
    )
        
    extract_dbip >> filter_ipv4 >> convert_into_ipv4
    extract_pub_log >> filter_remove_col >> convert_into_ipv4_pub
    [convert_into_ipv4, convert_into_ipv4_pub] >> map_ip_country >> load