package no.ohuen.fourthd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import no.ohuen.fourthd.exception.AlreadyConnectedException;
import no.ohuen.fourthd.exception.NotInitializedException;

/**
 *
 * @author 100tsa
 */
public class FOURD {

    private static final String DEFAULT_IMAGE_TYPE = "jpg";
    private final int MAX_STRING_NUMBER = 255;
    private final boolean USE_BASE64 = false;
    private final String PROTOCOL_VERSION = "13.0";
    private final int MAX_COL_TYPES_LENGHT = 4096;
    private final int VERBOSE = 1;

    SSLSocket socket;

    private boolean connected = false;
    private boolean init = false;
    /*Command number used for
     LOGIN, STATEMENT, ETC*/
    int idCnx = 0;
    int status;
    long errorCode;
    String errorString;
    String prefferedImageTypes = DEFAULT_IMAGE_TYPE;
    int timeout;

    long updatedRow;

    private FOURD() {
        this.init = true;
    }

    public static FOURD init() {
        return new FOURD();
    }

    public final boolean fourd_connect(String host, String user, String password, int port) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        if (!this.init) {
            throw new NotInitializedException();
        }
        if (this.connected) {
            throw new AlreadyConnectedException();
        }
        //connect
        final SSLContext context = SSLContext.getInstance("SSL");
        context.init(null, new TrustManager[]{//dummy SSL coz KSS uses selfsigned certificate
            new X509TrustManager() {
                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        }, new java.security.SecureRandom());
        this.socket = (SSLSocket) context.getSocketFactory().createSocket(host, port);
        this.socket.setUseClientMode(true);
        this.socket.startHandshake();
        this.idCnx = 1;

        if (dblogin(this, 1, user, password, this.prefferedImageTypes) != 0) {
            System.err.println("Error: in login function");
            this.connected = false;
            return false;
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            System.out.println(inputLine);
        }

        in.close();

        socket.close();

        return true;

    }

    private int dblogin(FOURD cnx, int i, String user, String password, String prefferedImageTypes) throws IOException {
        FOURD_RESULT state = new FOURD_RESULT();

        _clear_atrr_cnx(cnx);

        //db login
        String loginStr;
        if (USE_BASE64) {
            try {
                String b64User = Base64.getEncoder().encodeToString(user.getBytes("UTF-8"));
                String b64Password = Base64.getEncoder().encodeToString(password.getBytes("UTF-8"));
                loginStr = String.format("%d LOGIN \r\nUSER-NAME-BASE64:%s\r\nUSER-PASSWORD-BASE64:%s\r\nPREFERRED-IMAGE-TYPES:%s\r\nREPLY-WITH-BASE64-TEXT:Y\r\nPROTOCOL-VERSION:%s\r\n\r\n", this.idCnx, b64User, b64Password, this.prefferedImageTypes, PROTOCOL_VERSION);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(FOURD.class.getName()).log(Level.SEVERE, null, ex);
                return 1;
            }
        } else {
            loginStr = String.format("%d LOGIN \r\nUSER-NAME:%s\r\nUSER-PASSWORD:%s\r\nPREFERRED-IMAGE-TYPES:%s\r\nREPLY-WITH-BASE64-TEXT:Y\r\nPROTOCOL-VERSION:%s\r\n\r\n", this.idCnx, user, password, this.prefferedImageTypes, PROTOCOL_VERSION);
        }

        Communications c = new Communications();
        c.socket_send(cnx, loginStr);

        if (receiv_check(cnx, state) != 0) {
            return 1;
        }

        return 0;
    }

    private void _clear_atrr_cnx(FOURD cnx) {
        cnx.errorCode = 0L;
        cnx.errorString = "";
        cnx.updatedRow = 0L;
    }

    private int receiv_check(FOURD cnx, FOURD_RESULT state) throws IOException {
        Communications c = new Communications();
        c.socket_receiv_header(cnx, state);

        if (treate_header_response(state) != 0) {
            System.err.println("Error in treate_header_response");

            cnx.status = state.status;
            cnx.errorCode = state.errorCode;
            cnx.errorString = state.errorString;
            return 1;
        }
        cnx.status = state.status;
        cnx.errorCode = state.errorCode;
        cnx.errorString = state.errorString;
        return 0;
    }

    private int treate_header_response(FOURD_RESULT state) {
        String header = state.header.toString();
        long ret_get_status = 0;
        //get status in the header
        state.elmt = new FOURD_ELEMENT();
        ret_get_status = _get_status(state.header, state.status, state.errorCode, state.errorString);
        if (ret_get_status < 0) {
            //Technical error in parse header status
            return 1;
        } else if (ret_get_status > 0) {
            //The header is error-header
            //nothing to do with error-header
            return 1;
        }
        //The header is ok-header
        //get Column-Count
        {
            char[] column_count = new char[MAX_STRING_NUMBER];
            if (get(header, "Column-Count", column_count, MAX_STRING_NUMBER) == 0) {
                state.rowType.nbColumn = (int) Integer.valueOf(new String(column_count));
                //memory allocate for column name and column type
                state.rowType.Column = new FOURD_COLUMN[state.rowType.nbColumn];

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Count:%d\n", state.rowType.nbColumn));
                }
            }
        }
        //get Column-Types
        {
            char[] column_type = new char[MAX_COL_TYPES_LENGHT];
            String column = null;
            int num = 0;
            if (get(header, "Column-Types", column_type, MAX_COL_TYPES_LENGHT) == 0) {

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Types => %s", new String(column_type)));
                }

                column = new String(column_type).split(" ")[0];
                if (column.length() != 0) {
                    do {

                        if (VERBOSE == 1) {
                            System.err.println(String.format("Column %d: %s (%s)\n", num + 1, column, stringFromType(typeFromString(column))));
                        }

                        if (num < state.rowType.nbColumn) {
                            state.rowType.Column[num].type = typeFromString(column);
                            state.rowType.Column[num].sType =  column;
                        } else {
                            if (VERBOSE == 1) {
                                System.err.println(String.format("Error: There is more columns than Column-Count"));
                            }
                        }
                        num++;
                        column = strtok_s(null, " ");
                    } while (column != null);
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("End of reading columns"));
                }
            }
        }
        //get Column-Aliases-Base64
        {
            String column_alias;
            String alias = null;
            int num = 0;
            String col_start;
            String col_fin;
            long base64_size = MAX_COL_TYPES_LENGHT;
            String section = "Column-Aliases-Base64";

            //Figure out the length of our section. fun with pointers!
            //Start by getting a pointer to the start of the section label
            col_start = strstr(header, section);
            if (col_start != null) {
                //advance the pointer by the length of the section label
                col_start += section.length();
                //and find the first : (probably the next character)
                col_start = strstr(col_start, ":");

                if (col_start != null) {
                    //after making sure we still have something to work with,
                    //advance to the next character after the ":", which is the
                    //start of our data
                    col_start++;

                    //now find the end. It should have a new line after it
                    col_fin = strstr(col_start, "\n");
                    if (col_fin != null) {
                        //we have pointers to the start and end of our data. So how long is it?
                        //just subtract the pointers!
                        base64_size = col_fin - col_start;
                    }
                }
            }
            //if we ran into any issues with the above manipulation, we just use the
            //default size of 2048 and pray it works :)
            column_alias = calloc(sizeof(char), base64_size + 5); //I always like to give a few bytes wiggle

            //char *context=null;
            if (get(header, "Column-Aliases-Base64", column_alias, base64_size) == 0) {
                /* delete the last espace char if exist */
                if (column_alias[strlen(column_alias) - 1] == ' ') {
                    column_alias[strlen(column_alias) - 1] = 0;
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Aliases-Base64 => '%s'\n", column_alias);
                }

                _alias_str_replace(column_alias);
                alias = strtok_s(column_alias, "\r");
                if (alias != null) {
                    do {
                        if (VERBOSE == 1) {
                            System.err.println(String.format("Alias %d: %s", num + 1, alias));
                        }

                        if (num < state.rowType.nbColumn) {
                            /* erase [] */
                            if (alias.startsWith("[") && alias.endsWith("]")) {
                                state.rowType.Column[num].sColumnName = alias.subSequence(1, alias.length()-1).toString();
                            } else {
                                state.rowType.Column[num].sColumnName = alias;
                            }
                        } else {
                            if (VERBOSE == 1) {
                                System.err.println(String.format("Error: There is more alias than Column-Count"));
                            }
                        }
                        num++;
                        alias = strtok_s(null, "\r");
                    } while (alias != null);
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("End reading alias"));
                }
            }
        }
        //get Row-Count
        {
            char[] row_count = new char[MAX_STRING_NUMBER];
            if (get(header, "Row-Count", row_count, MAX_STRING_NUMBER) == 0) {
                state.rowCount = (int) Integer.valueOf(new String(row_count));

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count:%d", state.rowCount));
                }
            }
        }
        //get Row-Count-Sent
        {
            char[] row_count = new char[MAX_STRING_NUMBER];
            if (get(header, "Row-Count-Sent", row_count, MAX_STRING_NUMBER) == 0) {

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count-Sent:\"%s\" <=lut\n", new String(row_count)));
                }
                state.rowCountSent = (int) Integer.valueOf(new String(row_count));

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count-Sent:%d\n", state.rowCountSent));
                }
            }
        }
        //get Statement-ID
        {
            char[] statement_id = new char[MAX_STRING_NUMBER];
            if (get(header, "Statement-ID", statement_id, MAX_STRING_NUMBER) == 0) {
                state.id_statement = Integer.valueOf(new String(statement_id));

                if (VERBOSE == 1) {
                    System.err.println(String.format("Statement-ID:%d\n", state.id_statement));
                }
            }
        }
        //Column-Updateability
        {
            char[] updateability = new char[MAX_COL_TYPES_LENGHT];
            //state->updateability=1;
            if (get(header, "Column-Updateability", updateability, MAX_COL_TYPES_LENGHT) == 0) {
                state.updateability = new String(updateability).contains("Y");

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Updateability:%s", new String(updateability)));
                    System.err.println(String.format("Column-Updateability:%s", state.updateability));
                }
            }
        }
        //get Result-Type
        {
            char[] result_type = new char[MAX_COL_TYPES_LENGHT];
            if (get(header, "Result-Type", result_type, MAX_COL_TYPES_LENGHT) == 0) {

                //if Result-Type containt more than 1 Result-type => multirequete => not supproted by this driver
                if (new String(result_type).trim().contains(" ")) {
                    //multiquery not supported by this driver

                    if (VERBOSE == 1) {
                        System.err.println(String.format("Result-Type:%s", new String(result_type)));
                        System.err.println(String.format("Error: Multiquery not supported"));
                    }

                    return 1;
                }
                state.resultType = resultTypeFromString(new String(result_type).trim());
                switch (state.resultType) {
                    case UPDATE_COUNT:
                        break;
                    case RESULT_SET:
                        break;
                    case UNKNOW:
                    default:
                        if (VERBOSE == 1) {
                            System.err.println(String.format("Error: %d Result-Type not supported", result_type));
                        }
                        break;
                }
            }
        }
        return 0;

    }

    private long _get_status(StringBuilder header, int status, long errorCode, String errorString) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private int get(String header, String columnCount, char[] column_count, int MAX_STRING_NUMBER) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private FOURD_TYPE typeFromString(String type) {
        if ("VK_BOOLEAN".equals(type)) {
            return FOURD_TYPE.VK_BOOLEAN;
        }
        if ("VK_BYTE".equals(type)) {
            return FOURD_TYPE.VK_BYTE;
        }
        if ("VK_WORD".equals(type)) {
            return FOURD_TYPE.VK_WORD;
        }
        if ("VK_LONG".equals(type)) {
            return FOURD_TYPE.VK_LONG;
        }
        if ("VK_LONG8".equals(type)) {
            return FOURD_TYPE.VK_LONG8;
        }
        if ("VK_REAL".equals(type)) {
            return FOURD_TYPE.VK_REAL;
        }
        if ("VK_FLOAT".equals(type)) {
            return FOURD_TYPE.VK_FLOAT;
        }
        if ("VK_TIMESTAMP".equals(type)) {
            return FOURD_TYPE.VK_TIMESTAMP;
        }
        if ("VK_TIME".equals(type)) {
            return FOURD_TYPE.VK_TIMESTAMP;
        }
        if ("VK_DURATION".equals(type)) {
            return FOURD_TYPE.VK_DURATION;
        }
        if ("VK_TEXT".equals(type)) {
            return FOURD_TYPE.VK_STRING;
        }
        if ("VK_STRING".equals(type)) {
            return FOURD_TYPE.VK_STRING;
        }
        if ("VK_BLOB".equals(type)) {
            return FOURD_TYPE.VK_BLOB;
        }
        if ("VK_IMAGE".equals(type)) {
            return FOURD_TYPE.VK_IMAGE;
        }
        return FOURD_TYPE.VK_UNKNOW;
    }

    private String stringFromType(FOURD_TYPE type) {
        switch (type) {
            case VK_BOOLEAN:
                return "VK_BOOLEAN";
            case VK_BYTE:
                return "VK_BYTE";
            case VK_WORD:
                return "VK_WORD";
            case VK_LONG:
                return "VK_LONG";
            case VK_LONG8:
                return "VK_LONG8";
            case VK_REAL:
                return "VK_REAL";
            case VK_FLOAT:
                return "VK_FLOAT";
            case VK_TIMESTAMP:
                return "VK_TIMESTAMP";
            case VK_TIME:
                return "VK_TIME";
            case VK_DURATION:
                return "VK_DURATION";
            case VK_STRING:
                return "VK_STRING";
            case VK_BLOB:
                return "VK_BLOB";
            case VK_IMAGE:
                return "VK_IMAGE";
            default:
                return "VK_UNKNOW";
        }
    }

    private FOURD_RESULT_TYPE resultTypeFromString(String trim) {
	if("Update-Count".equals(trim))
		return FOURD_RESULT_TYPE.UPDATE_COUNT;
	if("Result-Set".equals(trim))
		return FOURD_RESULT_TYPE.RESULT_SET;
	return FOURD_RESULT_TYPE.UNKNOW;
    }
}