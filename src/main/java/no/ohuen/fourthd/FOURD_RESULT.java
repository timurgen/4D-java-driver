package no.ohuen.fourthd;

/**
 *
 * @author 100tsa
 */
public class FOURD_RESULT {

    FOURD cnx;
    StringBuilder header;
    int headerSize;

    /*state of statement (OK or KO)*/
 /*FOURD_OK or FOURD_ERRROR*/
    int status;
    long errorCode;
    String errorString;

    /*result of parse header
	  RESULT_SET for select
	  UPDATE_COUNT for insert, update, delete*/
    FOURD_RESULT_TYPE resultType;

    /*Id of statement used with 4D SQL-server*/
    int id_statement;
    /*Id of command use for request */
    int id_command;
    /*updateability is true or false */
    boolean updateability;

    /*total of row count */
    int rowCount;

    /*row count in data buffer
	  for little select, row_count_sent = row_count
	  for big select, row_count_sent = 100 for the first result_set
     */
    int rowCountSent;
    /*num of the first row
	for the first response in big select
	with default parametre on serveur : 0 */
    int firstRow;

    /* row_type of this statement
	   containe column count, column name and column type*/
    FOURD_ROW_TYPE rowType;

    /*data*/
    FOURD_ELEMENT elmt ;

    /*current row index*/
    int numRow;

    public FOURD_RESULT() {
        this.header = new StringBuilder();
    }
    
    
}
