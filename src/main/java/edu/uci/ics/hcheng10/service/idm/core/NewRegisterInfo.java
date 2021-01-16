package edu.uci.ics.hcheng10.service.idm.core;

import edu.uci.ics.hcheng10.service.idm.IDMService;
import edu.uci.ics.hcheng10.service.idm.logger.ServiceLogger;
import edu.uci.ics.hcheng10.service.idm.models.RegisterRequestModel;

import java.sql.*;
import java.util.ArrayList;

public class NewRegisterInfo {

    public static void insertIntoPlevelIfNotExist() {
        try  {
            String query = "INSERT INTO privilege_level (plevel, pname)\n" +
                    "SELECT * FROM (SELECT 1, 'ROOT') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT plevel FROM privilege_level WHERE plevel = 1\n" +
                    ") LIMIT 1;";
            String query2 = "INSERT INTO privilege_level (plevel, pname)\n" +
                    "SELECT * FROM (SELECT 2, 'ADMIN') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT plevel FROM privilege_level WHERE plevel = 2\n" +
                    ") LIMIT 1;";
            String query3 = "INSERT INTO privilege_level (plevel, pname)\n" +
                    "SELECT * FROM (SELECT 3, 'EMPLOYEE') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT plevel FROM privilege_level WHERE plevel = 3\n" +
                    ") LIMIT 1;";
            String query4 = "INSERT INTO privilege_level (plevel, pname)\n" +
                    "SELECT * FROM (SELECT 4, 'SERVICE') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT plevel FROM privilege_level WHERE plevel = 4\n" +
                    ") LIMIT 1;";
            String query5 = "INSERT INTO privilege_level (plevel, pname)\n" +
                    "SELECT * FROM (SELECT 5, 'USER') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT plevel FROM privilege_level WHERE plevel = 5\n" +
                    ") LIMIT 1;";
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
            PreparedStatement ps3 = IDMService.getCon().prepareStatement(query3);
            PreparedStatement ps4 = IDMService.getCon().prepareStatement(query4);
            PreparedStatement ps5 = IDMService.getCon().prepareStatement(query5);
            ps.executeUpdate();
            ServiceLogger.LOGGER.info("Insertion plevel:" + ps.toString());
            ps2.executeUpdate();
            ps3.executeUpdate();
            ps4.executeUpdate();
            ps5.executeUpdate();
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Insertion failed.");
            e.printStackTrace();
        }
    }

    public static void insertIntoSessionStatus() {
        try  {
            String query = "INSERT INTO session_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 1, 'Active') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM session_status WHERE status_id = 1\n" +
                    ") LIMIT 1;";
            String query2 = "INSERT INTO session_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 2, 'Closed') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM session_status WHERE status_id = 2\n" +
                    ") LIMIT 1;";
            String query3 = "INSERT INTO session_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 3, 'Expired') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM session_status WHERE status_id = 3\n" +
                    ") LIMIT 1;";
            String query4 = "INSERT INTO session_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 4, 'Revoked') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM session_status WHERE status_id = 4\n" +
                    ") LIMIT 1;";
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
            PreparedStatement ps3 = IDMService.getCon().prepareStatement(query3);
            PreparedStatement ps4 = IDMService.getCon().prepareStatement(query4);
            ps.executeUpdate();
            ServiceLogger.LOGGER.info("Insertion session_status:" + ps.toString());
            ps2.executeUpdate();
            ps3.executeUpdate();
            ps4.executeUpdate();
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Insertion failed.");
            e.printStackTrace();
        }
    }

    public static void insertIntoUserStatus() {
        try  {
            String query = "INSERT INTO user_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 1, 'Online') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM user_status WHERE status_id = 1\n" +
                    ") LIMIT 1;";
            String query2 = "INSERT INTO user_status (status_id, status)\n" +
                    "SELECT * FROM (SELECT 2, 'Offline') AS tmp\n" +
                    "WHERE NOT EXISTS (\n" +
                    "    SELECT status_id FROM user_status WHERE status_id = 2\n" +
                    ") LIMIT 1;";

            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
            ps.executeUpdate();
            ServiceLogger.LOGGER.info("Insertion user_status:" + ps.toString());
            ps2.executeUpdate();
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Insertion failed.");
            e.printStackTrace();
        }
    }

    public static int insertNewUser(RegisterRequestModel requestModel, String salt, String hashedPassword) {
        int code = 0;
        try {
            // Construct the query
//            String query1 =  "INSERT INTO session_status (status_id, status)" +
//                            " VALUES (?, ?);";
//            String query2 =  "INSERT INTO session (session_id, email, status, expr_time)" +
//                            " VALUES (?, ?, ?, ?);";
//            String query3 = "INSERT INTO privilege_level (plevel, pname)" +
//                            " VALUES (?, ?);";
            String query4 = "INSERT INTO user (email, status, plevel, salt, pword)" +
                            " VALUES (?, ?, ?, ?, ?);";
//            String query5 = "INSERT INTO user_status (status_id, status)" +
//                            " VALUES (?,?);";


            // Create the prepared statement
//            PreparedStatement ps1 = IDMService.getCon().prepareStatement(query1);
//            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
//            PreparedStatement ps3 = IDMService.getCon().prepareStatement(query3);
            PreparedStatement ps4 = IDMService.getCon().prepareStatement(query4);
//            PreparedStatement ps5 = IDMService.getCon().prepareStatement(query5);
            // disable foreign key checks
//            ps1.executeUpdate("SET FOREIGN_KEY_CHECKS=0");
//            // Set the arguments
//            ps1.setInt(1, newSession.getSessionID().hashCode());
//            ps1.setString(2, "Active");
//            ps2.setString(1, newSession.getSessionID().toString());
//            ps2.setString(2, requestModel.getEmail());
//            ps2.setInt(3, newSession.getSessionID().hashCode());
//            Timestamp time = newSession.getExprTime();
//            ServiceLogger.LOGGER.info("Time stamp should be: " + time);
//            ps2.setTimestamp(4, time);
//            ps3.setInt(1, 1);
//            ps3.setString(2, requestModel.getEmail());
            ps4.setString(1, requestModel.getEmail());
            ps4.setInt(2, 1);
            ps4.setInt(3, 5);
            ps4.setString(4, salt);
            ps4.setString(5, hashedPassword);
//            ps5.setInt(1,newSession.getSessionID().hashCode());
//            ps5.setString(2, "Register/placeholder");

            // Save the query result to a ResultSet so records may be retrieved
//            ServiceLogger.LOGGER.info("Trying insertion: " + ps1.toString());
//            code = ps1.executeUpdate();
//            ServiceLogger.LOGGER.info("Trying insertion: " + ps2.toString());
//            code = ps2.executeUpdate();
//            ServiceLogger.LOGGER.info("Trying insertion: " + ps3.toString());
//            code = ps3.executeUpdate();
            code = ps4.executeUpdate();
            ServiceLogger.LOGGER.info("Trying insertion: " + ps4.toString());
            ServiceLogger.LOGGER.info("Insertion succeeded.");

//            code = ps5.executeUpdate();

        } catch (SQLIntegrityConstraintViolationException e) {
            ServiceLogger.LOGGER.warning("Duplicate emails.");
            e.printStackTrace();
            return -2;
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Insertion failed.");
            e.printStackTrace();
            return -1;
        }
        return code;
    }

    public static String buildStudentQuery(ArrayList<String> cols,
                                           RegisterRequestModel requestModel){

        String SELECT = "SELECT email";
        String FROM = " FROM user";
        String WHERE = " WHERE 1=1";

        for(String c:cols){
            SELECT += (", " + c);
        }

        if (requestModel.getEmail() != null) {
            WHERE += " && email LIKE '%" + requestModel.getEmail() + "%'";
        }

        if (requestModel.getPassword() != null) {
            WHERE += " && password LIKE '%" + requestModel.getPassword() + "%'";
        }

        return SELECT + FROM + WHERE;
    }

}
