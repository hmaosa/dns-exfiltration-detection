import json
import pandas as pd
from dns_utils import shannon_entropy

def process_dns(input_file):
    if not input_file:
        return None, None

    with open(input_file) as f:
        dns_data = json.load(f)

    df = pd.json_normalize(dns_data)

    # Preserve empty-question entries for analysis
    empty_q_df = df[df['questions'].isna() | df['questions'].apply(lambda q: isinstance(q, list) and len(q) == 0)].copy()

    # Proceed with entries that have questions
    df = df[df['questions'].notna() & df['questions'].apply(lambda q: isinstance(q, list) and len(q) > 0)].copy()
    df = df.explode('questions').reset_index(drop=True)

    # If exploded questions still exist, normalize them
    if not df.empty and df['questions'].notna().any():
        q_exp = pd.json_normalize(df['questions'])
        df = pd.concat([df.drop(columns=['questions']), q_exp], axis=1)
    else:
        print("No valid question entries to normalize.")
        return None, empty_q_df

    # Safely handle qname-based features
    if 'qname' in df.columns:
        df = df[df['qname'].notna()].copy()
        df['qname_length'] = df['qname'].apply(len)
        df['qname_entropy'] = df['qname'].apply(shannon_entropy)
    else:
        print("'qname' not found in normalized questions. Skipping length/entropy features.")
        df['qname_length'] = None
        df['qname_entropy'] = None

    # Convert timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    return df, empty_q_df