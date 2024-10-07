#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>

using namespace std;

#define BUFFER_SIZE 1024
// #define ESC '\x1b'
#define ESC '|'

enum UserActions
{
    REGISTER = 1,
    LOG_IN = 2,
    CREATE_GROUP = 3,
    JOIN_GROUP = 4,
    LEAVE_GROUP = 5,
    LIST_GROUP_JOIN_REQ = 6,
    ACCEPT_JOIN_REQ = 7,
    LIST_GROUP = 8,
    LOG_OUT = 9
};

struct client_info
{
    string username;
    string password;
};
client_info *client = new client_info;

struct socket_info
{
    string ip;
    int port;
};

socket_info *tracker_addr = new socket_info;
socket_info *client_addr = new socket_info;

bool loggedin = false;
bool flag = true;

void tokenise(string str, struct socket_info *tokens)
{
    size_t end = str.find(':');
    if (end != string::npos)
    {
        tokens->ip = str.substr(0, end);
        tokens->port = stoi(str.substr(end + 1).c_str());
    }
}

void tokenise(string &msg, vector<string> &msg_vector, char delimiter = ' ')
{

    msg_vector.clear();

    int msg_len = msg.length();
    string token;

    // int vector_len = 0;

    for (int i = 0; i < msg_len; i++)
    {
        if (msg[i] == delimiter)
        {
            if (token.length() > 0)
            {
                msg_vector.push_back(token);
                token.clear();
                // vector_len++;
            }
        }
        else
        {
            token.push_back(msg[i]);
        }
    }

    if (token.length() > 0)
    {
        msg_vector.push_back(token);
    }

    // return vector_len;
}

int getChoiceFromCommand(string str)
{
    if (str.compare("create_user") == 0)
    {
        return REGISTER;
    }
    else if (str.compare("login") == 0)
    {
        return LOG_IN;
    }
    else if (str.compare("create_group") == 0)
    {
        return CREATE_GROUP;
    }
    else if (str.compare("join_group") == 0)
    {
        return JOIN_GROUP;
    }
    else if (str.compare("leave_group") == 0)
    {
        return LEAVE_GROUP;
    }
    else if (str.compare("list_requests") == 0)
    {
        return LIST_GROUP_JOIN_REQ;
    }
    else if (str.compare("accept_request") == 0)
    {
        return ACCEPT_JOIN_REQ;
    }
    else if (str.compare("list_groups") == 0)
    {
        return LIST_GROUP;
    }
    else if (str.compare("logout") == 0)
    {
        return LOG_OUT;
    }
}

void makeHeader(int choice, string &header)
{

    int header_len = 4;
    char buffer[8];

    snprintf(buffer, sizeof(buffer), "%.*d", header_len, choice);
    header = buffer;
}

int getMessage(vector<string> &tokens, string &send_msg, int command_type)
{
    string header;
    makeHeader(command_type, header);
    send_msg.append(header);
    send_msg.push_back(ESC);

    // enum and switch
    if (command_type == REGISTER || command_type == LOG_IN)
    {
        if (!loggedin)
        {
            if (tokens.size() < 3)
            {
                cerr << "create_user: Too few arguments\n";
                return 1;
            }
            else if (tokens.size() > 3)
            {
                cerr << "create_user: Too many arguments\n";
                return 1;
            }
            else
            {
                send_msg.append(tokens[1]);
                send_msg.push_back(ESC);

                send_msg.append(tokens[2]);
                send_msg.push_back(ESC);

                send_msg.append(client_addr->ip);
                send_msg.push_back(ESC);


                send_msg.append(to_string(client_addr->port));
                send_msg.push_back(ESC);
            }
        }
    }
    if (tokens[0] == "login")
    {
    }
    if (tokens[0] == "create_group")
    {
    }
    if (tokens[0] == "join_group")
    {
    }
    if (tokens[0] == "leave_group")
    {
    }
    if (tokens[0] == "list_requests")
    {
    }
    if (tokens[0] == "accept_request")
    {
    }
    if (tokens[0] == "list_groups")
    {
    }
    if (tokens[0] == "logout")
    {
        flag = false;
        send_msg.append(client->username);
        send_msg.push_back(ESC);
    }

    return 0;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        cerr << "Err: Too few arguments\n";
        return 1;
    }
    else if (argc > 3)
    {
        cerr << "Err: Too many arguments\n";
        return 1;
    }

    const char *tracker_file_path = argv[2];
    const char *client_info = argv[1];
    const int trackerno = 1;
    int fd = open(tracker_file_path, O_RDONLY);

    if (fd == -1)
    {
        perror("open");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;
    string curr_tracker;

    int tracker_count = 1;
    while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0)
    {
        ssize_t i;
        for (i = 0; i < bytesRead; ++i)
        {
            char ch = buffer[i];

            if (ch == '\n')
            {

                if (tracker_count == trackerno)
                    break;
                tracker_count++;
                curr_tracker.clear();
            }
            else
            {
                curr_tracker += ch;
            }
        }
        if (i != bytesRead)
            break;
    }
    close(fd);

    tokenise(curr_tracker, tracker_addr);
    tokenise(client_info, client_addr);

    int sockfd;
    struct sockaddr_in serv_addr;
    char buff[BUFFER_SIZE];
    FILE *fp;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
    }

    // TODO: explore getaddrinfo
    struct hostent *server = gethostbyname(tracker_addr->ip.c_str());

    if (server == NULL)
    {
        cerr << "Err: no such host\n";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(tracker_addr->ip.c_str());
    serv_addr.sin_port = htons(tracker_addr->port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
    }

    do
    {
        string command;
        getline(cin, command);

        vector<string> tokens;
        tokenise(command, tokens);

        int command_type = getChoiceFromCommand(tokens[0]);
        string send_msg;
        getMessage(tokens, send_msg, command_type);

        // TODO: maxmsgsize
        send(sockfd, send_msg.c_str(), send_msg.length(), 0);
        // Read and print the message from the client
        int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received > 0)
        {
            buffer[bytes_received] = '\0'; // Null-terminate the string
            cout << "Message from client: " << buffer << std::endl;
        }

    } while (flag);

    close(sockfd);

    return 0;
}