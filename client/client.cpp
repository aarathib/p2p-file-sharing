#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>

using namespace std;

#define BUFFER_SIZE 1024
#define PIECE_SIZE (512 * 1024) // 512 KB

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
    LOG_OUT = 9,
    UPLOAD_FILE = 10,
    DOWNLOAD_FILE = 11,
    LIST_FILES = 12,
    SHOW_DOWNLOADS = 13,
    STOP_SHARE = 14
};

struct socket_info
{
    string ip;
    int port;
};

struct global_info
{
    bool loggedin = false;
    string userid;
    int sockfd;
    pthread_t thread;
};

socket_info *tracker_addr = new socket_info;
socket_info *client_addr = new socket_info;
global_info *global = new global_info;

// bool loggedin = false;
// string userid = "";
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

string toHexString(const unsigned char *hash, int length)
{
    stringstream ss;
    for (int i = 0; i < length; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

string computeSHA1(const unsigned char *data, size_t length)
{
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, length, hash);
    return toHexString(hash, SHA_DIGEST_LENGTH);
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
    else if (str.compare("upload_file") == 0)
    {
        return UPLOAD_FILE;
    }
    else if (str.compare("download_file") == 0)
    {
        return DOWNLOAD_FILE;
    }
    else if (str.compare("list_files") == 0)
    {
        return LIST_FILES;
    }
    else if (str.compare("show_downloads") == 0)
    {
        return SHOW_DOWNLOADS;
    }
    else if (str.compare("stop_share") == 0)
    {
        return STOP_SHARE;
    }

    return -1;
}

void makeHeader(int choice, string &header)
{

    int header_len = 4;
    char buffer[8];

    snprintf(buffer, sizeof(buffer), "%.*d", header_len, choice);
    header = buffer;
}

void getMessage(vector<string> &tokens, string &send_msg, int command_type)
{
    string header;
    makeHeader(command_type, header);
    send_msg.append(header);
    send_msg.push_back(ESC);

    // enum and switch
    if (command_type == REGISTER || command_type == LOG_IN)
    {
        if (!global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cerr << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cerr << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(tokens[1]);
                send_msg.push_back(ESC);

                send_msg.append(tokens[2]);
                send_msg.push_back(ESC);

                if (command_type == REGISTER)
                {
                    send_msg.append(client_addr->ip);
                    send_msg.push_back(ESC);

                    send_msg.append(to_string(client_addr->port));
                    send_msg.push_back(ESC);
                }
            }
        }
        else
        {
            cout << "Already registered and Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == CREATE_GROUP || command_type == JOIN_GROUP || command_type == LEAVE_GROUP || command_type == LIST_GROUP_JOIN_REQ)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 2)
            {
                cout << tokens[0] << ": Too few arguments";
                send_msg.clear();
            }
            else if (tokens.size() > 2)
            {
                cout << tokens[0] << ": Too many arguments";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');
                send_msg.append(tokens[1]);
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == LIST_GROUP)
    {
        if (!global->loggedin)
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == ACCEPT_JOIN_REQ)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cout << tokens[0] << ": Too few arguments";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');
                send_msg.append(tokens[1]);
                send_msg.push_back('|');
                send_msg.append(tokens[2]);
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == UPLOAD_FILE)
    {
        if (!global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cout << tokens[0] << ": Too few arguments";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments";
                send_msg.clear();
            }
            else
            {
                string gpid = tokens[2];
                send_msg.append(gpid);
                send_msg.push_back('|');

                const char *filepath = tokens[1].c_str();
                int fd = open(filepath, O_RDONLY);
                if (fd == -1)
                {
                    perror("open");
                    // TODO: what to do
                }

                unsigned char buffer[PIECE_SIZE];
                ssize_t bytesRead;
                vector<string> piecewise_hash;

                EVP_MD_CTX *fileContext = EVP_MD_CTX_new();          // Create context
                EVP_DigestInit_ex(fileContext, EVP_sha1(), nullptr); // Initialize SHA-1

                while ((bytesRead = read(fd, buffer, PIECE_SIZE)) > 0)
                {
                    string pieceHash = computeSHA1(buffer, bytesRead);
                    piecewise_hash.push_back(pieceHash);
                    EVP_DigestUpdate(fileContext, buffer, bytesRead); // Update hash with data
                }

                if (bytesRead == -1)
                {
                    perror("read");
                    close(fd);
                    EVP_MD_CTX_free(fileContext); // Free context
                    // TODO: what to do
                    // return 1;
                }

                close(fd);

                unsigned char completeHash[SHA_DIGEST_LENGTH];
                EVP_DigestFinal_ex(fileContext, completeHash, nullptr); // Finalize hash
                EVP_MD_CTX_free(fileContext);                           // Free context

                string completeHashString = toHexString(completeHash, SHA_DIGEST_LENGTH);

                send_msg.append(completeHashString);
                send_msg.push_back('|');

                for (int i = 0; i < piecewise_hash.size(); i++)
                {
                    send_msg.append(piecewise_hash[i].substr(0, 20));
                }
                send_msg.push_back('|');
            }
        }
        else
        {
            cout << "User not Logged In";
            send_msg.clear();
        }
    }
    else if (command_type == LOG_OUT)
    {
        if (global->loggedin)
        {
            send_msg.append(global->userid);
            send_msg.push_back(ESC);
        }
        else
        {
            cout << "User not Logged In";
            send_msg.clear();
        }
    }
    else
    {
        cout << "Invalid command";
        send_msg.clear();
    }
}

void checkStatus(vector<string> tokens)
{
    int choice = stoi(tokens[0]);
    int success = (tokens[1] == "200");
    switch (choice)
    {
    case 1:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case 2:
    {
        if (success)
        {
            global->loggedin = true;
            global->userid = tokens[2];
            cout << tokens[3] << '\n';
        }
        else
            cout << tokens[2] << '\n';
        break;
    }
    case 3:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case 4:
    {
        cout << tokens[2] << '\n';
        break;
    }

    case 5:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case 6:
    {
        if (tokens.size() == 3)
            cout << tokens[2] << '\n';
        else
        {
            cout << "Pending requests are:\n";
            for (int i = 2; i < tokens.size(); i++)
            {
                cout << tokens[i] << '\n';
            }
        }

        break;
    }
    case 7:
    {
        cout << tokens[1] << "\n";
        break;
    }

    case 8:
    {
        if (tokens.size() == 2)
            cout << tokens[1] << '\n';
        else
        {
            cout << "Available groups are:\n";
            for (int i = 1; i < tokens.size(); i++)
            {
                cout << tokens[i] << '\n';
            }
        }
        break;
    }
    case 9:
    {
        if (success)
        {
            global->loggedin = false;
            flag = false;
        }

        cout << tokens[2] << '\n';

        break;
    }
    }
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

        if (!send_msg.empty())
        {
            // TODO: maxmsgsize
            cout << "send: " << send_msg << '\n';
            cout << "len: " << send_msg.length();
            // send(sockfd, send_msg.c_str(), send_msg.length(), 0);
            // Read and print the message from the client
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0'; // Null-terminate the string
                vector<string> res;
                string reply = string(buffer);
                // cout << reply;
                tokenise(reply, res, '|');
                checkStatus(res);
            }
        }

    } while (flag);

    close(sockfd);

    return 0;
}