#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>
#include <sys/stat.h>

using namespace std;

#define BUFFER_SIZE 1024
#define PIECE_SIZE (512 * 1024) // 512 KB
#define BACKLOG 10

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

struct piece_info
{
    int index, filesize;
    string piecehash;
};

struct global_info
{
    bool loggedin = false;
    string userid;
    int sockfd;
    pthread_t thread;
};

struct port_struct
{
    int sockfd;
    int newfd;
    struct sockaddr_in cli_addr;
    socklen_t clilen;
};

struct peer_file_info
{
    string filename;
    int filesize;
    vector<socket_info> peer_sockets;
    vector<piece_info> file_piece;
};

struct download_info
{
    socket_info socket;
    string filename;
    int piece_no;
    int piece_size;
    string piece_hash;
    int dest_fd;
    pthread_mutex_t *file_write_mutex;
};

socket_info *tracker_addr = new socket_info;
socket_info *client_addr = new socket_info;
global_info *global = new global_info;
unordered_map<string, string> todownload;

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
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 2)
            {
                cout << tokens[0] << ": Too many arguments\n";
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
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments\n";
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
        if (global->loggedin)
        {
            if (tokens.size() < 3)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 3)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                send_msg.append(global->userid);
                send_msg.push_back('|');

                string gpid = tokens[2];
                send_msg.append(gpid);
                send_msg.push_back('|');

                const char *filepath = tokens[1].c_str();

                struct stat file_struct;
                stat(filepath, &file_struct);
                if (!S_ISDIR(file_struct.st_mode))
                {
                    int pos = -1;
                    for (int i = 0; i < tokens[1].size(); i++)
                    {
                        if (tokens[1][i] == '/')
                            pos = i;
                    }
                    string filename = tokens[1].substr(pos + 1, tokens[1].size());
                    send_msg.append(filename);
                    send_msg.push_back('|');
                    send_msg.append(to_string(file_struct.st_size));
                    send_msg.push_back('|');

                    int fd = open(filepath, O_RDONLY);
                    if (fd == -1)
                    {
                        perror("open");
                        // TODO: what to do
                    }

                    unsigned char buffer[PIECE_SIZE];
                    ssize_t bytesRead;
                    vector<string> piecewise_hash;
                    ssize_t last_piece_size;

                    SHA_CTX shaContext;     // Create context
                    SHA1_Init(&shaContext); // Initialize SHA-1 context

                    while ((bytesRead = read(fd, buffer, PIECE_SIZE)) > 0)
                    {
                        last_piece_size = bytesRead;
                        string pieceHash = computeSHA1(buffer, bytesRead);
                        piecewise_hash.push_back(pieceHash);
                        SHA1_Update(&shaContext, buffer, bytesRead); // Update hash with data
                    }

                    if (bytesRead == -1)
                    {
                        perror("read");
                        close(fd);
                        // EVP_MD_CTX_free(fileContext); // Free context
                        // TODO: what to do
                        // return 1;
                    }

                    close(fd);

                    unsigned char completeHash[SHA_DIGEST_LENGTH];
                    SHA1_Final(completeHash, &shaContext); // Finalize SHA-1 // Finalize hash
                    // EVP_MD_CTX_free(fileContext);                           // Free context

                    string completeHashString = toHexString(completeHash, SHA_DIGEST_LENGTH);

                    send_msg.append(to_string(last_piece_size));
                    send_msg.push_back('|');
                    send_msg.append(completeHashString);
                    send_msg.push_back('|');

                    for (int i = 0; i < piecewise_hash.size(); i++)
                    {
                        send_msg.append(piecewise_hash[i]);
                        send_msg.push_back('$');
                    }
                    send_msg.push_back('|');
                }
                else
                {
                    cout << "Given path is of directory\n";
                    send_msg.clear();
                }
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == DOWNLOAD_FILE)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 4)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 4)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
                string gpid = tokens[1];
                string filename = tokens[2];
                string dest = tokens[3];
                send_msg.append(gpid);
                send_msg.push_back('|');
                send_msg.append(filename);
                send_msg.push_back('|');
                // send_msg.append(dest);
                // send_msg.push_back('|');
                todownload[filename] = dest;
            }
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else if (command_type == LIST_FILES)
    {
        if (global->loggedin)
        {
            if (tokens.size() < 2)
            {
                cout << tokens[0] << ": Too few arguments\n";
                send_msg.clear();
            }
            else if (tokens.size() > 2)
            {
                cout << tokens[0] << ": Too many arguments\n";
                send_msg.clear();
            }
            else
            {
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
    else if (command_type == LOG_OUT)
    {
        if (global->loggedin)
        {
            send_msg.append(global->userid);
            send_msg.push_back(ESC);
        }
        else
        {
            cout << "User not Logged In\n";
            send_msg.clear();
        }
    }
    else
    {
        cout << "Invalid command\n";
        send_msg.clear();
    }
}

int handleDownload(int sockfd, string filename)
{
    char buffer[PIECE_SIZE];
    string send_msg = "ping";
    send(sockfd, send_msg.c_str(), send_msg.length(), 0);
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0'; // Null-terminate the string
        string reply = string(buffer);
        if (reply == "ping")
            cout << "Connected to peer\n";
    }

    send(sockfd, filename.c_str(), filename.length(), 0);
    int fd = open(todownload[filename].c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1)
    {
        perror("open");
        return 1;
    }
    while ((bytes_received = recv(sockfd, buffer, sizeof(buffer), 0)) > 0)
    {

        // Writing to file
        if (write(fd, buffer, bytes_received) == -1)
        {
            perror("Err");
            return -1;
        }
    }
    cout << "Download complete\n";
    return 0;
}

int handleDownload1(int sockfd, string filename, int piece, string &hash, int fd, pthread_mutex_t *w_mutex, int piece_size)
{
    char buffer[PIECE_SIZE];
    string send_msg = "ping";
    send(sockfd, send_msg.c_str(), send_msg.length(), 0);
    // why -1
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0'; // Null-terminate the string
        string reply = string(buffer);
        if (reply == "ping")
            cout << "Connected to peer\n";
    }

    cout << "filename: " << filename << '\n';
    string fileinfo = filename + '|' + to_string(piece);
    // cout << "before open " << todownload[filename] << '\n';
    send(sockfd, fileinfo.c_str(), fileinfo.length(), 0);
    // int fd = open(todownload[filename].c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    // if (fd == -1)
    // {
    //     cout << "after open " << todownload[filename] << '\n';
    //     perror("openxyz");
    //     return 1;
    // }
    ssize_t total_bytes_received = 0;
    while (total_bytes_received < piece_size)
    {
        bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);

        pthread_mutex_lock(w_mutex);
        lseek(fd, piece * PIECE_SIZE + total_bytes_received, SEEK_SET);
        total_bytes_received += bytes_received;

        cout << "writing by piece " << piece << '\n';
        if (write(fd, buffer, bytes_received) == -1)
        {
            string msg = "piece writing error " + to_string(piece);
            perror(msg.c_str());
            return -1;
        }
        // dargs->peer.file_offset += bytes_read;
        pthread_mutex_unlock(w_mutex);

        // Writing to file
        // if (write(fd, buffer, bytes_received) == -1)
        // {
        //     perror("Err");
        //     return -1;
        // }
    }
    if (total_bytes_received < piece_size)
    {
        cerr << "Warning: Incomplete piece received for piece " << piece << endl;
        return 1;
    }
    else
    {
        cout << "Download complete for piece " << piece << "\n";
        return 0;
    }
}

void *downloadFile(void *arg)
{
    peer_file_info *dfile = (peer_file_info *)arg;
    // socket_info *peer_addr = (socket_info *)arg;
    string filename = dfile->filename;
    auto peer = dfile->peer_sockets[0];
    cout << "meet my peer: " << peer.ip << ":" << peer.port << '\n';
    struct sockaddr_in serv_addr;
    // char buff[BUFFER_SIZE];
    // FILE *fp;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
    }

    // TODO: explore getaddrinfo
    struct hostent *server = gethostbyname(peer.ip.c_str());

    if (server == NULL)
    {
        cerr << "Err: no such host\n";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(peer.ip.c_str());
    serv_addr.sin_port = htons(peer.port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
    }

    handleDownload(sockfd, filename);

    close(sockfd);
    pthread_exit(NULL);
}

void *downloadFile1(void *arg)
{
    download_info *meta = (download_info *)arg;
    // socket_info *peer_addr = (socket_info *)arg;
    string filename = meta->filename;
    socket_info peer = meta->socket;
    int piece_index = meta->piece_no;
    int piece_size = meta->piece_size;
    string piece_hash = meta->piece_hash;
    int fd = meta->dest_fd;
    // mutex

    cout << "meet my peer: " << peer.ip << ":" << peer.port << '\n';
    struct sockaddr_in serv_addr;
    // char buff[BUFFER_SIZE];

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("socket");
    }

    // TODO: explore getaddrinfo
    struct hostent *server = gethostbyname(peer.ip.c_str());

    if (server == NULL)
    {
        cerr << "Err: no such host\n";
    }

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(peer.ip.c_str());
    serv_addr.sin_port = htons(peer.port);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("connect");
    }

    int reponse=handleDownload1(sockfd, filename, piece_index, piece_hash, fd, meta->file_write_mutex, piece_size);
    if(reponse==0){

        int sockfdx = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfdx < 0)
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
    string respond="got it";
        send(sockfd, respond.c_str(), respond.length(), 0);
    }

    close(sockfd);
    pthread_exit(NULL);
}

void handleMultiplePieceDownload(peer_file_info *multiplePiece)
{
    cout << "REached multiple piece download\n";
    vector<socket_info> user = multiplePiece->peer_sockets;
    vector<piece_info> pieces = multiplePiece->file_piece;
    int num_pieces = pieces.size();
    int num_peers = user.size();
    string dest = todownload[multiplePiece->filename];
    int fd = open(dest.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0)
    {
        perror("open");
        // TODO: return maybe
    }

    // Preallocate space for the file by setting its size
    if (ftruncate(fd, multiplePiece->filesize) == -1)
    {
        perror("ftruncate");
        close(fd);
        return;
    }

    pthread_t fileThreads[num_pieces];
    pthread_mutex_t write_mutex;
    pthread_mutex_init(&write_mutex, NULL);

    for (int i = 0; i < num_pieces; i++)
    {
        int peer = i % num_peers;
        download_info *meta = new download_info;
        meta->socket = user[peer];
        meta->filename = multiplePiece->filename;
        meta->piece_no = i;
        meta->piece_size = pieces[i].filesize;
        meta->piece_hash = pieces[i].piecehash;
        meta->dest_fd = fd;
        meta->file_write_mutex = &write_mutex;
        pthread_create(&fileThreads[i], NULL, downloadFile1, (void *)meta);
    }

    for (int i = 0; i < num_pieces; i++)
    {
        pthread_join(fileThreads[i], NULL);
    }

    close(fd);
    pthread_mutex_destroy(&write_mutex);
}

int checkStatus(vector<string> tokens)
{
    cout << "Reached check status\n";
    // cout << "stoi1: " << tokens[0];
    int choice = stoi(tokens[0]);
    int success = (tokens[1] == "200");
    switch (choice)
    {
    case REGISTER:
    {
        cout << tokens[2] << '\n';
        return 1;
        break;
    }
    case LOG_IN:
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
    case CREATE_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case JOIN_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }

    case LEAVE_GROUP:
    {
        cout << tokens[2] << '\n';
        break;
    }
    case LIST_GROUP_JOIN_REQ:
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
    case ACCEPT_JOIN_REQ:
    {
        cout << tokens[1] << "\n";
        break;
    }

    case LIST_GROUP:
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
    case LOG_OUT:
    {
        if (success)
        {
            global->loggedin = false;
            flag = false;
        }

        cout << tokens[2] << '\n';

        break;
    }
    case UPLOAD_FILE:
    {
        cout << tokens[1] << '\n';
        break;
    }
    case DOWNLOAD_FILE:
    {
        cout << "Reached case: \n";
        if (tokens[1] == "400")
        {
            cout << tokens[2] << '\n';
        }
        else
        {
            vector<socket_info> peers;
            vector<piece_info> pieces;
            // cout << "stoi3: " << tokens[2];
            string filename = tokens[2];
            int filesize = stoi(tokens[3]);
            int peer_count = stoi(tokens[4]);
            cout << "filename: " << filename << ";filesize: " << filesize << "; peercout: " << peer_count << '\n';
            int index = 5;
            for (int i = 0; i < 2 * peer_count; i++)
            {
                socket_info socket;
                socket.ip = tokens[index + i];
                i++;
                // cout << "stoi4: " << tokens[index + i + 1];
                socket.port = stoi(tokens[index + i]);
                peers.push_back(socket);
            }
            cout << "peers collected\n";
            index += 2 * peer_count;
            // cout << "stoi5: " << tokens[index];
            int lastpiece_size = stoi(tokens[index++]);
            cout << "last piece: " << lastpiece_size << '\n';
            // cout << "stoi6: " << tokens[index];
            int piece_count = stoi(tokens[index++]);
            for (int i = 0; i < piece_count; i++)
            {
                piece_info piece;
                piece.index = i;
                piece.filesize = (i == piece_count - 1 ? lastpiece_size : PIECE_SIZE);
                piece.piecehash = tokens[index + i];
                pieces.push_back(piece);
            }
            cout << "pieces colleted\n";

            // pthread_t download_thread;
            peer_file_info *peer_connect = new peer_file_info;
            peer_connect->filename = filename;
            peer_connect->filesize = filesize;
            peer_connect->file_piece = pieces;
            peer_connect->peer_sockets = peers;
            cout << "download info ready peer and filepiece\n";
            handleMultiplePieceDownload(peer_connect);
            // pthread_create(&download_thread, NULL, downloadFile, (void *)peer_connect);
        }

        break;
    }
    case LIST_FILES:
    {
        if (tokens[1] == "200")
        {
            for (int i = 2; i < tokens.size(); i++)
            {
                cout << tokens[i] << "\n";
            }
            if (tokens.size() == 2)
            {
                cout << "No shareable files available in the group\n";
            }
        }
        else
            cout << tokens[2] << '\n';
        break;
    }
    }
}

void *listenClients(void *arg)
{
    port_struct *port_info = (port_struct *)arg;
    char buffer[PIECE_SIZE];

    bool flag = true;

    // while (flag)
    // {
    // TODO: why -1
    ssize_t bytes_received = recv(port_info->newfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        cout << "Message from peer: " << buffer << endl;
        string reply_msg = "ping";
        cout << "reply sent\n";
        send(port_info->newfd, reply_msg.c_str(), reply_msg.length(), 0);
        recv(port_info->newfd, buffer, sizeof(buffer) - 1, 0);
        cout << "reply receibed\n";
        vector<string> tokens;
        reply_msg = string(buffer);
        cout << "repply msg:" << reply_msg << '\n';
        tokenise(reply_msg, tokens, '|');
        cout << "tokenised\n";
        for (int i = 0; i < tokens.size(); i++)
        {
            cout << "token: " << tokens[i] << '\n';
        }
        string filename = tokens[0];
        int piece = stoi(tokens[1]);
        cout << "filename: " << filename << " piece: " << piece << '\n';
        cout << "before open " << filename << '\n';
        int fd = open(filename.c_str(), O_RDONLY);
        if (fd == -1)
        {
            cout << "after open " << filename << '\n';
            perror("openxyz");
            pthread_exit(NULL);
        }
        cout << "file opend\n";
        off_t offset = piece * PIECE_SIZE;
        lseek(fd, offset, SEEK_SET);

        while ((bytes_received = read(fd, buffer, sizeof(buffer))) > 0)
        {
            cout << "sending\n";
            send(port_info->newfd, buffer, bytes_received, 0);
        }
        close(fd);
        cout << "Upload complete\n";
    }
    else if (bytes_received == 0)
    {
        cout << "Client disconnected\n";
    }
    else
    {
        perror("recv");
        flag = false;
    }

    // Close sockets
    close(port_info->newfd);
    delete port_info;
    pthread_exit(NULL);
}

void *peerCommn(void *arg)
{
    socket_info *client_addr = (socket_info *)arg;
    char buffer[BUFFER_SIZE];

    struct sockaddr_in serv_addr;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }
    cout << "socket created successfully\n";

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_port = htons(client_addr->port);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(client_addr->ip.c_str());

    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("setsockopt");
        close(sockfd);
        exit(1);
    }
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        exit(1);
    }
    cout << "Binded successfully\n";

    // socket listening
    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    int thread_count = 0;
    cout << "Client started in Port\n";
    while (1)
    {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);

        int newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0)
        {
            perror("accept");
        }
        cout << "Connected\n";

        port_struct *port_info = new port_struct;
        port_info->sockfd = sockfd;
        port_info->newfd = newsockfd;
        port_info->cli_addr = cli_addr;
        port_info->clilen = clilen;

        pthread_t listen_thread;
        // TODO: return value from pthread_create
        pthread_create(&listen_thread, NULL, listenClients, (void *)port_info);
    }

    close(sockfd);
    pthread_exit(NULL);
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
    // TODO: ping all and find up
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

    struct sockaddr_in serv_addr;
    // char buff[BUFFER_SIZE];
    // FILE *fp;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

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
    //----------------------------------------------------------------
    // const char *client_file_path = argv[3];
    // fd = open(client_file_path, O_RDONLY);

    // if (fd == -1)
    // {
    //     perror("open");
    //     return 1;
    // }

    // curr_tracker.clear();
    // vector<string> clients;
    // while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0)
    // {
    //     cout << "reading file\n";
    //     ssize_t i;
    //     for (i = 0; i < bytesRead; ++i)
    //     {
    //         char ch = buffer[i];

    //         if (ch == '\n')
    //         {
    //             clients.push_back(curr_tracker);
    //             curr_tracker.clear();
    //         }
    //         else
    //         {
    //             curr_tracker += ch;
    //         }
    //     }
    //     if (i != bytesRead)
    //         break;
    // }
    // clients.push_back(curr_tracker);
    // close(fd);

    // cout << "got ports of 2\n";
    // string peer_port, client_port;
    // client_port = string(client_info);
    // cout << "client port: " << client_port << '\n';
    // cout << " port1: " << clients[0] << '\n';
    // cout << " port2: " << clients[1] << '\n';
    // if (client_port == clients[0])
    //     peer_port = clients[1];
    // else
    //     peer_port = clients[0];
    // cout << "peer: " << peer_port << '\n';
    // cout << "client: " << client_port << '\n';
    // cout << "got peer port\n";
    // struct socket_info *peer_addr = new socket_info;
    // const char *peer_str = peer_port.c_str();
    // tokenise(peer_str, peer_addr);
    // cout << "got peer port struct\n";
    // cout << peer_addr->ip << ":" << peer_addr->port << '\n';
    // cout << "going to sleep\n";
    // sleep(20);
    // cout << "woke up\n";
    //-----------------------------------------------------------
    pthread_t peer_thread;
    pthread_create(&peer_thread, NULL, peerCommn, (void *)client_addr);

    // if (peer_port == "127.0.0.1:6002")
    // {
    //     pthread_t download_thread;
    //     pthread_create(&download_thread, NULL, downloadFile, (void *)peer_addr);
    // }

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
            // cout << "send: " << send_msg << '\n';
            // cout << "len: " << send_msg.length() << '\n';
            send(sockfd, send_msg.c_str(), send_msg.length(), 0);
            // Read and print the message from the client
            int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0'; // Null-terminate the string
                vector<string> res;
                string reply = string(buffer);
                // cout << reply;
                tokenise(reply, res, '|');
                cout << "going to check status\n";
                checkStatus(res);
            }
        }

    } while (flag);

    close(sockfd);

    return 0;
}