from airflow.sdk import DAG, Asset
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
from airflow.providers.common.sql.operators.sql import SQLExecuteQueryOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
import pandas as pd
from io import StringIO
import ipaddress

asset_log = Asset("postgres://postgres_dwh/dwh/public/stg_logs")
asset_pays = Asset("postgres://postgres_dwh/dwh/public/inventaire_pays")


def process_and_load_logs(task_instance):
    """Nettoie les logs et les charge dans une table de staging"""
    data = task_instance.xcom_pull(task_ids='extract_pub_log')
    df = pd.read_csv(StringIO(data))
    
    if 'Destination_IP' in df.columns:
        df = df.drop(columns=['Destination_IP'])
        
    df['Source_IP_int'] = df['Source_IP'].apply(lambda ip: int(ipaddress.IPv4Address(ip)) if pd.notnull(ip) else 0)
    
    hook = PostgresHook(postgres_conn_id='postgres_dwh')
    engine = hook.get_sqlalchemy_engine()
    
    df.to_sql('stg_logs', engine, if_exists='replace', index=False)
    print("Logs chargés dans la table stg_logs.")

def process_and_load_pays(task_instance):
    """Vérifie si le chargement est nécessaire, puis charge le référentiel des pays"""
    hook = PostgresHook(postgres_conn_id='postgres_dwh')
    engine = hook.get_sqlalchemy_engine()
    
    try:
        count = pd.read_sql("SELECT COUNT(*) FROM inventaire_pays", engine).iloc[0,0]
        if count > 0:
            print("Optimisation : L'inventaire des pays existe déjà en base. Extraction ignorée.")
            return
    except Exception:
        pass 
        
    data = task_instance.xcom_pull(task_ids='extract_dbip')
    df = pd.read_csv(StringIO(data), names=['ip_start_range', 'ip_end_range', 'country_code'])
    df_filtered = df[df['ip_start_range'].str.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', na=False)]
    
    df_filtered['ip_start_int'] = df_filtered['ip_start_range'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    df_filtered['ip_end_int'] = df_filtered['ip_end_range'].apply(lambda ip: int(ipaddress.IPv4Address(ip)))
    
    df_filtered.to_sql('inventaire_pays', engine, if_exists='replace', index=False)
    print("Référentiel des pays chargé dans la table inventaire_pays.")

# 1er DAG : Extraction des Logs
with DAG(dag_id='dag_intrusion_log', schedule=None, catchup=False) as dag_log:
    
    extract_pub_log = HttpOperator(
        task_id='extract_pub_log',
        method='GET',
        endpoint='public_network_logs.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    
    load_logs_to_db = PythonOperator(
        task_id='load_logs_to_db',
        python_callable=process_and_load_logs,
        outlets=[asset_log] # Airflow 3 : on utilise l'Asset
    )
    
    extract_pub_log >> load_logs_to_db

# 2ème DAG : Inventaire des Pays
with DAG(dag_id='dag_intrusion_pays', schedule=[asset_log], catchup=False) as dag_pays:
    
    extract_dbip = HttpOperator(
        task_id='extract_dbip',
        method='GET',
        endpoint='dbip-country-lite-2026-01.csv',
        http_conn_id='httpdata_apache_intrusion'
    )
    
    load_pays_to_db = PythonOperator(
        task_id='load_pays_to_db',
        python_callable=process_and_load_pays,
        outlets=[asset_pays]
    )
    
    extract_dbip >> load_pays_to_db

#3ème DAG : Jointure en Base de données
sql_mapping_query = """
    DROP TABLE IF EXISTS intrusion_finale;
    CREATE TABLE intrusion_finale AS
    SELECT l.*, p.country_code
    FROM stg_logs l
    LEFT JOIN inventaire_pays p
    ON l."Source_IP_int" >= p.ip_start_int AND l."Source_IP_int" <= p.ip_end_int;
"""

with DAG(dag_id='dag_intrusion_db', schedule=[asset_pays], catchup=False) as dag_db:
    
    apply_mapping_in_db = SQLExecuteQueryOperator(
        task_id='apply_mapping_in_db',
        conn_id='postgres_dwh',
        sql=sql_mapping_query
    )