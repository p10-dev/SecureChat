import argparse
from chat_server import ChatServer
from chat_client import ChatClient

def main():
    parser = argparse.ArgumentParser(description='Secure Chat')
    parser.add_argument('mode', choices=['server', 'client'], 
                       help='Run as server (central hub) or client (user)')
    parser.add_argument('--id', help='Unique client ID (required for client mode)')
    parser.add_argument('--host', default='127.0.0.1', 
                       help='Server IP address (default: localhost)')
    parser.add_argument('--port', type=int, default=9999, 
                       help='Server port number (default: 9999)')
    
    args = parser.parse_args()
    
    if args.mode == 'server':
        ChatServer(args.host, args.port).start()
    elif args.mode == 'client':
        if not args.id:
            print("Error: Client ID required (use --id YourName)")
            return
        ChatClient(args.id, args.host, args.port).start()
    else:
        print("Invalid mode selected")

if __name__ == "__main__":
    main()
