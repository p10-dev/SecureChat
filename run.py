import argparse
from chat_server import ChatServer
from chat_client import ChatClient

def main():
    parser = argparse.ArgumentParser(description='Secure Chat')
    parser.add_argument('mode', choices=['server', 'client'], help='Run as server or client')
    parser.add_argument('--id', help='Client ID (required for client)')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9999)
    args = parser.parse_args()

    if args.mode == 'server':
        ChatServer(args.host, args.port).start()
    elif args.mode == 'client':
        if not args.id:
            print('Client ID required with --id')
            return
        ChatClient(args.id, args.host, args.port).start()
    else:
        print('Invalid mode')

if __name__ == '__main__':
    main()
