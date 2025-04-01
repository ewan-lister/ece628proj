from projectclasses.client import Client
import logging
import time
import pandas as pd
import sys
import statistics
import matplotlib.pyplot as plt
import numpy as np

def setup_logging():
    """Configure minimal logging for benchmarking"""
    logging.basicConfig(level=logging.ERROR)

def run_handshake(cipher_suite, num_trials=10):
    """Run handshake multiple times and collect timing data"""
    results = {
        'cert_processing': [],
        'server_messages': [],
        'cert_send': [],
        'key_exchange': [],
        'cert_verify': [],
        'cipher_spec': [],
        'total_time': []
    }
    
    for i in range(num_trials):
        try:
            client = Client('localhost', 8444, [cipher_suite])
            
            # Capture start time for total connection
            start = time.time()
            
            # Connect and perform handshake
            client.connect()
            
            # Get timing data from the last handshake
            if cipher_suite == Client.RSA_SUITE:
                handshake = client.rsa_handshake
            else:
                handshake = client.dhe_handshake
            
            # Extract timing data from the handshake
            results['cert_processing'].append(client.last_cert_time)
            results['server_messages'].append(client.last_server_msgs_time)
            results['cert_send'].append(client.last_cert_send_time)
            results['key_exchange'].append(client.last_key_exchange_time)
            results['cert_verify'].append(client.last_verify_time)
            results['cipher_spec'].append(client.last_cipher_spec_time)
            results['total_time'].append(time.time() - start)
            
            client.close()
            time.sleep(0.1)  # Brief pause between trials
            
        except Exception as e:
            print(f"Trial {i} failed: {e}")
            continue
    
    return results

def calculate_statistics(data):
    """Calculate statistics for each timing metric"""
    stats = {}
    for metric, values in data.items():
        if values:  # Check if we have data
            stats[f"{metric}_mean"] = statistics.mean(values)
            stats[f"{metric}_stddev"] = statistics.stdev(values)
            stats[f"{metric}_min"] = min(values)
            stats[f"{metric}_max"] = max(values)
    return stats

def plot_key_exchange_comparison(rsa_results, dhe_results, save_path='key_exchange_comparison.png'):
    """Generate plot comparing RSA and DHE key exchange times"""
    plt.figure(figsize=(12, 6))
    
    # Create trial numbers for x-axis
    trials = range(1, len(rsa_results['key_exchange']) + 1)
    
    # Plot both key exchange times
    plt.plot(trials, rsa_results['key_exchange'], 'b-', label='RSA', alpha=0.7)
    plt.plot(trials, dhe_results['key_exchange'], 'r-', label='DHE', alpha=0.7)
    
    # Add mean lines
    rsa_mean = np.mean(rsa_results['key_exchange'])
    dhe_mean = np.mean(dhe_results['key_exchange'])
    plt.axhline(y=rsa_mean, color='b', linestyle='--', alpha=0.5, label=f'RSA mean: {rsa_mean:.6f}s')
    plt.axhline(y=dhe_mean, color='r', linestyle='--', alpha=0.5, label=f'DHE mean: {dhe_mean:.6f}s')
    
    # Customize plot
    plt.title('RSA vs DHE Key Exchange Times')
    plt.xlabel('Trial Number')
    plt.ylabel('Time (seconds)')
    plt.grid(True, alpha=0.3)
    plt.legend()
    
    # Save plot
    plt.savefig(save_path)
    print(f"\nPlot saved to {save_path}")

def plot_timing_boxplots(rsa_results, dhe_results, save_path='timing_boxplots.png'):
    """Generate boxplots for all timing metrics"""
    plt.figure(figsize=(15, 8))
    
    # Prepare data for boxplot
    metrics = ['cert_processing', 'server_messages', 'cert_send', 
              'key_exchange', 'cert_verify', 'cipher_spec', 'total_time']
    
    rsa_data = [rsa_results[metric] for metric in metrics]
    dhe_data = [dhe_results[metric] for metric in metrics]
    
    # Create positions for boxplots
    positions = np.arange(len(metrics)) * 3
    width = 0.8
    
    # Create boxplots
    plt.boxplot(rsa_data, positions=positions-width, 
                labels=[''] * len(metrics), patch_artist=True,
                boxprops=dict(facecolor='lightblue', color='blue'),
                medianprops=dict(color='darkblue'))
    
    plt.boxplot(dhe_data, positions=positions+width,
                labels=[''] * len(metrics), patch_artist=True,
                boxprops=dict(facecolor='lightpink', color='red'),
                medianprops=dict(color='darkred'))
    
    # Customize plot
    plt.xticks(positions, [m.replace('_', ' ').title() for m in metrics], 
               rotation=45)
    plt.ylabel('Time (seconds)')
    plt.title('RSA vs DHE Timing Metrics Distribution')
    
    # Add legend
    plt.plot([], [], color='lightblue', linewidth=10, label='RSA')
    plt.plot([], [], color='lightpink', linewidth=10, label='DHE')
    plt.legend()
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(save_path)
    print(f"Boxplot saved to {save_path}")

def main():
    setup_logging()
    num_trials = 50  # Number of trials for each cipher suite
    
    print(f"Running {num_trials} trials for each cipher suite...")
    
    # Test RSA
    print("\nTesting RSA handshake...")
    rsa_results = run_handshake(Client.RSA_SUITE, num_trials)
    rsa_stats = calculate_statistics(rsa_results)
    
    # Test DHE
    print("\nTesting DHE handshake...")
    dhe_results = run_handshake(Client.DHE_SUITE, num_trials)
    dhe_stats = calculate_statistics(dhe_results)
    
    # Create DataFrame for detailed results
    detailed_results = {
        'RSA': pd.DataFrame(rsa_results),
        'DHE': pd.DataFrame(dhe_results)
    }
    
    # Create DataFrame for summary statistics
    summary_stats = pd.DataFrame({
        'RSA': rsa_stats,
        'DHE': dhe_stats
    }).transpose()
    
    # Save results to Excel
    with pd.ExcelWriter('tls_benchmark_results.xlsx') as writer:
        summary_stats.to_excel(writer, sheet_name='Summary Statistics')
        detailed_results['RSA'].to_excel(writer, sheet_name='RSA Detailed')
        detailed_results['DHE'].to_excel(writer, sheet_name='DHE Detailed')
    
    print("\nResults saved to tls_benchmark_results.xlsx")
    
    # Print key statistics
    print("\nKey Exchange Times (seconds):")
    print(f"RSA: {rsa_stats['key_exchange_mean']:.6f} ± {rsa_stats['key_exchange_stddev']:.6f}")
    print(f"DHE: {dhe_stats['key_exchange_mean']:.6f} ± {dhe_stats['key_exchange_stddev']:.6f}")
    
    # Generate plots
    plot_key_exchange_comparison(rsa_results, dhe_results)
    plot_timing_boxplots(rsa_results, dhe_results)

if __name__ == "__main__":
    main()