package no.ohuen.fourthd;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
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
    private final int PAGE_SIZE = 100;
    private final int MAX_STRING_NUMBER = 255;
    private final String OUTPUT_MODE = "RELEASE";
    private final int FOURD_OK = 0;
    private final int FOURD_ERROR = 1;

    private final boolean USE_BASE64 = false;
    private final boolean STATEMENT_BASE64 = false;

    private final String PROTOCOL_VERSION = "0.1a";
    private final int MAX_COL_TYPES_LENGHT = 4096;
    private final int ERROR_STRING_LENGTH = 2048;
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
    String session_id;

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
        this.connected = true;
        this.errorCode = 0;
        this.errorString = "";

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
                loginStr = String.format("%03d LOGIN \r\n"
                        + "USER-NAME-BASE64:%s\r\n"
                        + "USER-PASSWORD-BASE64:%s\r\n"
                        + "PREFERRED-IMAGE-TYPES:%s\r\n"
                        + "REPLY-WITH-BASE64-TEXT:Y\r\n"
                        + "PROTOCOL-VERSION:%s\r\n\r\n", this.idCnx, b64User, b64Password, this.prefferedImageTypes, PROTOCOL_VERSION);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(FOURD.class.getName()).log(Level.SEVERE, null, ex);
                return 1;
            }
        } else {
            loginStr = String.format("%03d LOGIN \r\n"
                    + "USER-NAME:%s\r\n"
                    + "USER-PASSWORD:%s\r\n"
                    + "PREFERRED-IMAGE-TYPES:%s\r\n"
                    + "REPLY-WITH-BASE64-TEXT:Y\r\n"
                    + "PROTOCOL-VERSION:%s\r\n\r\n", this.idCnx, user, password, this.prefferedImageTypes, PROTOCOL_VERSION);
        }
        if (VERBOSE == 1) {
            System.out.println("Send:\r\n" + loginStr);
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
            String columnCount;
            if ((columnCount = get(header, "Column-Count")) != null) {
                state.rowType.nbColumn = (int) Integer.valueOf(columnCount);
                //memory allocate for column name and column type
                state.rowType.Column = new FOURD_COLUMN[state.rowType.nbColumn];

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Count:%d\n", state.rowType.nbColumn));
                }
            }
        }
        //contains SESSION-ID

        {
            String sessionId;
            if ((sessionId = get(header, "Session-ID")) != null) {
                this.session_id = sessionId;
            }
        }
        //get Column-Types
        {
            String columnTypes;
            String column;
            int num = 0;
            if ((columnTypes = get(header, "Column-Types")) != null) {

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Types => %s", columnTypes));
                }

                column = columnTypes.split(" ")[0];
                if (column.length() != 0) {
                    do {

                        if (VERBOSE == 1) {
                            System.err.println(String.format("Column %d: %s (%s)\n", num + 1, column, stringFromType(typeFromString(column))));
                        }

                        if (num < state.rowType.nbColumn) {
                            state.rowType.Column[num].type = typeFromString(column);
                            state.rowType.Column[num].sType = column;
                        } else {
                            if (VERBOSE == 1) {
                                System.err.println(String.format("Error: There is more columns than Column-Count"));
                            }
                        }
                        num++;
                        column = column.split(" ")[0];
                    } while (column != null);
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("End of reading columns"));
                }
            }
        }
        //get Column-Aliases-Base64
        {
            char[] column_alias;
            String alias = null;
            int num = 0;
            String col_start;
            String col_fin;
            long base64_size = MAX_COL_TYPES_LENGHT;
            String section = "Column-Aliases-Base64";

            //Figure out the length of our section. fun with pointers!
            //Start by getting a pointer to the start of the section label
            int indexOfSection = header.indexOf(section);
            if (indexOfSection != -1) {
                col_start = header.substring(indexOfSection);
                //advance the pointer by the length of the section label
                //col_start += section.length();
                //and find the first : (probably the next character)
                int indexOfFirstColon = col_start.indexOf(":");
//                col_start = strstr(col_start, ":");

                if (indexOfFirstColon != -1) {
                    //after making sure we still have something to work with,
                    //advance to the next character after the ":", which is the
                    //start of our data
                    col_start = col_start.substring(indexOfFirstColon);

                    //now find the end. It should have a new line after it
                    //col_fin = strstr(col_start, "\n");
                    int indexOfFirstLineBreak = col_start.indexOf("\n");
                    if (indexOfFirstLineBreak != -1) {
                        //we have pointers to the start and end of our data. So how long is it?
                        //just subtract the pointers!
                        //base64_size = col_fin - col_start;
                        base64_size = indexOfFirstLineBreak - indexOfFirstColon;
                    }
                }
            }
            //if we ran into any issues with the above manipulation, we just use the
            //default size of 2048 and pray it works :)
            //column_alias = calloc(sizeof(char), base64_size + 5); //I always like to give a few bytes wiggle
            //column_alias = new char[(int) base64_size + 5];
            String columnAlias;
            //char *context=null;
            if ((columnAlias = get(header, "Column-Aliases-Base64")) != null) {
                /* delete the last espace char if exist */
                if (columnAlias.endsWith(" ")) {
                    //don't need null terminator in java
                    //column_alias[column_alias.length - 1] = 0;
                    //column_alias[column_alias.length - 1] = '\n';
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Aliases-Base64 => %s", columnAlias));
                }

                //_alias_str_replace(column_alias);
                alias = columnAlias.split("\r\n")[0];
                if (alias != null) {
                    do {
                        if (VERBOSE == 1) {
                            System.err.println(String.format("Alias %d: %s", num + 1, alias));
                        }

                        if (num < state.rowType.nbColumn) {
                            /* erase [] */
                            if (alias.startsWith("[") && alias.endsWith("]")) {
                                state.rowType.Column[num].sColumnName = alias.subSequence(1, alias.length() - 1).toString();
                            } else {
                                state.rowType.Column[num].sColumnName = alias;
                            }
                        } else {
                            if (VERBOSE == 1) {
                                System.err.println(String.format("Error: There is more alias than Column-Count"));
                            }
                        }
                        num++;
                        alias = alias.split("\r")[0];
                    } while (alias != null);
                }

                if (VERBOSE == 1) {
                    System.err.println(String.format("End reading alias"));
                }
            }
        }
        //get Row-Count
        {
            String rowCount;
            if ((rowCount = get(header, "Row-Count")) != null) {
                state.rowCount = (int) Integer.valueOf(rowCount);

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count:%d", state.rowCount));
                }
            }
        }
        //get Row-Count-Sent
        {
            String rowCount;
            if ((rowCount = get(header, "Row-Count-Sent")) != null) {

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count-Sent:\"%s\" <=lut\n", rowCount));
                }
                state.rowCountSent = (int) Integer.valueOf(rowCount);

                if (VERBOSE == 1) {
                    System.err.println(String.format("Row-Count-Sent:%d\n", state.rowCountSent));
                }
            }
        }
        //get Statement-ID
        {
            String statementId;
            if ((statementId = get(header, "Statement-ID")) != null) {
                state.id_statement = Integer.valueOf(statementId);

                if (VERBOSE == 1) {
                    System.err.println(String.format("Statement-ID:%d\n", state.id_statement));
                }
            }
        }
        //Column-Updateability
        {
            String updateability;
            if ((updateability = get(header, "Column-Updateability")) != null) {
                state.updateability = updateability.contains("Y");

                if (VERBOSE == 1) {
                    System.err.println(String.format("Column-Updateability:%s", updateability));
                    System.err.println(String.format("Column-Updateability:%s", state.updateability));
                }
            }
        }
        //get Result-Type
        {
            char[] result_type = new char[MAX_COL_TYPES_LENGHT];
            String resultType;
            if ((resultType = get(header, "Result-Type")) != null) {

                //if Result-Type containt more than 1 Result-type => multirequete => not supproted by this driver
                if (resultType.trim().contains(" ")) {
                    //multiquery not supported by this driver

                    if (VERBOSE == 1) {
                        System.err.println(String.format("Result-Type:%s", resultType));
                        System.err.println(String.format("Error: Multiquery not supported"));
                    }

                    return 1;
                }
                state.resultType = resultTypeFromString(resultType.trim());
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

    private long _get_status(StringBuilder header, Integer status, Long errorCode, String errorString) {
        char[] eStatus = new char[50];

        status = FOURD_ERROR;

        if (!header.toString().contains(" ")) {
            return -1L;
        }

        if (!header.toString().contains("\n")) {
            return -1;
        }
        String statusStr = header.toString().split("\r\n")[0];

        if (statusStr.contains("OK")) {
            errorCode = 0L;
            errorString = null;
            status = FOURD_OK;
            return 0L;
        } else {
            status = FOURD_ERROR;
            String errorCodeStr = get(header.toString(), "Error-Code");
            errorCode = Long.valueOf(errorCodeStr);
            errorString = get(header.toString(), "Error-Description");
            return errorCode;
        }
    }

    private String get(String msg, String section) {
        if (!msg.contains(section)) {
            return null;
        }
        if (!msg.contains(":")) {
            return null;
        }

        String msgValue = msg.substring(msg.indexOf(section)).split(":")[1].split("\r\n")[0];

        if (section.contains("-Base64")) {
            return new String(Base64.getDecoder().decode(msgValue));
        }
        return msgValue;
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
        if ("Update-Count".equals(trim)) {
            return FOURD_RESULT_TYPE.UPDATE_COUNT;
        }
        if ("Result-Set".equals(trim)) {
            return FOURD_RESULT_TYPE.RESULT_SET;
        }
        return FOURD_RESULT_TYPE.UNKNOW;
    }

    private void _alias_str_replace(char[] list_alias) {
//	char[] loc=list_alias;
//	char[] locm= null;
//	while((loc=strstr(loc,"] ["))!=NULL) {
//		if((loc-list_alias)>1) {
//			locm=loc;
//			locm--;
//			if(locm[0]!=']') {
//				loc[1]='\r';
//			}
//			else {
//				loc++;
//			}
//		}
//		else {
//			loc[1]='\r';
//		}
//	}
    }

    FOURD_RESULT fourd_query(String query) throws IOException {
        FOURD_RESULT result = new FOURD_RESULT();
        result.cnx = this;
        this.idCnx++;

        if (_query(this, 3, query, result, this.prefferedImageTypes, PAGE_SIZE) == 0) {
            result.numRow = -1;
            return result;
        } else {
            fourd_free_result(result);
            return null;
        }
    }

    private int _query(FOURD cnx, int id_cnx, String request, FOURD_RESULT result, String image_type, int res_size) throws IOException {
        Communications c = new Communications();
        String msg;
        FOURD_RESULT res;

        if (VERBOSE == 1) {
            System.err.println("---Debug the _query");
        }

        _clear_atrr_cnx(cnx);

        if (!_valid_query(cnx, request)) {
            return 1;
        }

        if (result != null) {
            res = result;
        } else {
            res = new FOURD_RESULT();
        }

        if (STATEMENT_BASE64) {

            String request_b64 = Base64.getEncoder().encodeToString(request.getBytes(Charset.defaultCharset()));
            String format_str = "%03d EXECUTE-STATEMENT\r\n"
                    + "STATEMENT-BASE64: %s\r\n"
                    + "OUTPUT-MODE: %s\r\n"
                    + "FIRST-PAGE-SIZE:%d\r\n"
                    + "PREFERRED-IMAGE-TYPES:%s\r\n\r\n";
            msg = String.format(format_str, id_cnx, request_b64, OUTPUT_MODE, res_size, image_type);

        } else {
            String format_str = "%03d EXECUTE-STATEMENT \r\n"
                    + "STATEMENT : %s\r\n"
                    + "Output-Mode:%s\r\n"
                    + "FIRST-PAGE-SIZE:%d\r\n"
                    + "PREFERRED-IMAGE-TYPES:%s\r\n\r\n";
            msg = String.format(format_str, id_cnx, request, OUTPUT_MODE, res_size, image_type);
        }
        cnx.updatedRow = -1;
        if (VERBOSE == 1) {
            System.out.println("Send:\r\n" + msg);
        }
        c.socket_send(cnx, msg);

        if (receiv_check(cnx, res) != 0) {
            return 1;
        }

        switch (res.resultType) {
            case UPDATE_COUNT:
                //get Update-count: Nb row updated
//                cnx.updatedRow = -1;
//                socket_receiv_update_count(cnx, res);
//                _free_data_result(res);
                break;
            case RESULT_SET:
                //get data
//                socket_receiv_data(cnx, res);
//                cnx.updatedRow = -1;
//                if (result == null) {
//                    _free_data_result(res);
//                }
                break;
            default:
                if (VERBOSE == 1) {
                    System.err.println("Error: Result-Type not supported in query");
                }
        }
        if (result == null) {
            //Free(res);
            //noop don't need to deallocate in Java
        }

        if (VERBOSE == 1) {
            System.out.println("---End of _query\n");
        }

        return 0;
    }

    private void fourd_free_result(FOURD_RESULT result) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private boolean _valid_query(FOURD cnx, String request) {
        if (_is_multi_query(request)) {
            cnx.errorCode = -5001;
            cnx.errorString = "MultiQuery not supported";
            return false;
        }
        return true;
    }

    private boolean _is_multi_query(String _request) {
        int i = 0;
        long len;
        boolean inCol = false;
        boolean inStr = false;
        int finFirst = 0;
        char car = 0;
        if (_request == null) {
            return false;
        }
        len = _request.length();
        char[] request = _request.toCharArray();
        if (len < 1) {
            return false;
        }
        for (i = 0; i < len; i++) {

            car = request[i];
            switch (car) {
                case '[':
                    /* start of 4D object name */
                    if (!inStr) {
                        if (!inCol) {
                            /* printf("["); */
                            inCol = true;
                        } else {
                            /* printf("_"); */
                        }
                    } else {
                        /* printf("s"); */
                    }
                    break;
                case ']':
                    if (inStr) {
                        /* printf("s"); */
                    } else if (inCol) {
                        inCol = false;
                        /* printf("]"); */
                    } else {
                        if (i > 1) {
                            /* check the previous charactere */
                            if (request[i - 1] == ']') {
                                /* not end of colomn name */
                                inCol = true;
                                /* printf("-"); */
                            } else {
                                inCol = false;
                                /* printf("]"); */
                            }
                        } else {
                            /* printf("_");*/
                        }
                    }

                    break;
                case '\'':
                    if (!inCol) {
                        /* printf("'");*/
                        if (inStr == false) {
                            inStr = true;
                        } else {
                            inStr = false;
                        }
                    } else {
                        /* printf("c"); */
                    }
                    break;
                case ';':
                    /* end of query */
                    if (!inCol && !inStr) {
                        finFirst = 1;
                        /* printf(";");*/
                    } else {
                        /*printf("_");*/
                    }
                    break;
                default:
                    if (inCol) {
                        /* printf("C"); */
                    } else if (inStr) {
                        /* printf("S"); */
                    } else if (car == ' ') {
                        /*printf(" ");*/
                    } else {
                        if (finFirst == 1) {
                            /* printf("X"); */
                            return true;
                        } else {
                            /* printf("*"); */
                        }
                    }
                    break;
            }

        }
        return false;
    }

    int fourd_close() throws IOException {
        if (dblogout(this, 4) != 0) {
            //return 1;
        }
        if (quit(this, 5) != 0) {
            //return 1;
        }
        this.socket.close();
        return 0;
    }

    private int dblogout(FOURD cnx, int i) throws IOException {
        FOURD_RESULT state = new FOURD_RESULT();
        _clear_atrr_cnx(cnx);
        String msg = String.format("%03d LOGOUT\r\n\r\n", i);
        if (VERBOSE == 1) {
            System.out.println("Send:\r\n" + msg);
        }
        Communications c = new Communications();
        c.socket_send(cnx, msg);
        if (receiv_check(cnx, state) != 0) {
            return 1;
        }
        return 0;

    }

    private int quit(FOURD cnx, int i) throws IOException {
        FOURD_RESULT state = new FOURD_RESULT();
        _clear_atrr_cnx(cnx);
        String msg = String.format("%03d QUIT\r\n\r\n", i);
        if (VERBOSE == 1) {
            System.out.println("Send:\r\n" + msg);
        }
        Communications c = new Communications();
        c.socket_send(cnx, msg);
        if (receiv_check(cnx, state) != 0) {
            return 1;
        }
        return 0;
    }
}
