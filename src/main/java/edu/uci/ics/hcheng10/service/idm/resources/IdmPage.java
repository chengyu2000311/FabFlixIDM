package edu.uci.ics.hcheng10.service.idm.resources;


import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import edu.uci.ics.hcheng10.service.idm.IDMService;
import edu.uci.ics.hcheng10.service.idm.core.NewRegisterInfo;
import edu.uci.ics.hcheng10.service.idm.core.RegisterInfo;
import edu.uci.ics.hcheng10.service.idm.logger.ServiceLogger;
import edu.uci.ics.hcheng10.service.idm.models.*;
import edu.uci.ics.hcheng10.service.idm.security.Crypto;
import edu.uci.ics.hcheng10.service.idm.security.Session;
import org.apache.commons.codec.binary.Hex;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;


@Path("idm") // Outer path
public class IdmPage {

    @Path("register")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response Register(@Context HttpHeaders headers, String jsonText) {
        RegisterRequestModel requestModel;
        LoginResponseModel responseModel;
        ObjectMapper mapper = new ObjectMapper();

        try {
            requestModel = mapper.readValue(jsonText, RegisterRequestModel.class);
        } catch (IOException e) {
            int resultCode;
            e.printStackTrace();
            if (e instanceof JsonParseException) {
                resultCode = -3;
                responseModel = new LoginResponseModel(resultCode, "JSON Parse Exception",null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (e instanceof JsonMappingException) {
                resultCode = -2;
                responseModel = new LoginResponseModel(resultCode, "JSON Mapping Exception",null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else {
                resultCode = -1;
                responseModel = new LoginResponseModel(resultCode, "Internal Server Error",null);
                ServiceLogger.LOGGER.severe("Internal Server Error");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
            }
        }

        try {
            ServiceLogger.LOGGER.info("Received request to register");
            ServiceLogger.LOGGER.info("Request:\n" + jsonText);

            String email = requestModel.getEmail();
            if (email == null || email.length() < 5 || email.length() > 128 /* a@b.c (5) is the mini length* 128 is db requirement */) {
                responseModel = new LoginResponseModel(-10, "Email address has invalid length.",null);
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }

            char [] password = requestModel.getPassword();
            if (password == null || password.length == 0) {
                responseModel = new LoginResponseModel(-12, "Password has invalid length.",null);
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (password.length < 7 || password.length > 16) {
                responseModel = new LoginResponseModel(12, "Password does not meet length requirements.",null);
                ServiceLogger.LOGGER.info("Password does not meet length requirements.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            }

            Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+@(.+)\\.(.+)$", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(email);

            if (!matcher.matches()) {
                responseModel = new LoginResponseModel(-11, "Email address has invalid format.",null);
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }

            boolean hasUpper = false, hasLower = false, hasNum = false;
            for (char i: password) {
                if (Character.isLowerCase(i)) hasLower = true;
                if (Character.isUpperCase(i)) hasUpper = true;
                if (Character.isDigit(i)) hasNum = true;
            }
            if (!(hasLower && hasUpper && hasNum)) {
                responseModel = new LoginResponseModel(13, "Password does not meet character requirements.",null);
                ServiceLogger.LOGGER.info("Password does not meet character requirements.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            }
            if (RegisterInfo.checkEmailExist(email)) {
                responseModel = new LoginResponseModel(16, "Email already in use.",null);
                ServiceLogger.LOGGER.info("Email already in use.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            }

            Session newSession = Session.createSession(email);
            // all conditions checks true
            byte[] salt = Crypto.genSalt();

            // Use the salt to hash the password
            byte[] hashedPassword = Crypto.hashPassword(password, salt, Crypto.ITERATIONS, Crypto.KEY_LENGTH);

            // Encode salt & password
            String encodedSalt = Hex.encodeHexString(salt);
            String encodedPassword = Hex.encodeHexString(hashedPassword);

            if (NewRegisterInfo.insertNewUser(requestModel, encodedSalt, encodedPassword)==-2) {
                responseModel = new LoginResponseModel(16, "Email already in use.",null);
                ServiceLogger.LOGGER.info("Email already in use.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            };

            responseModel = new LoginResponseModel(110, "User registered successfully.",null);

            ServiceLogger.LOGGER.info("User registered successfully.");
            return Response.status(Response.Status.OK).entity(responseModel).build();
        } catch(Exception ee) {
            responseModel = new LoginResponseModel(-1, "500 Internal Server Error.",null);
            ServiceLogger.LOGGER.info("500 Internal Server Error.");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
        }


    }

    @Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response Login(@Context HttpHeaders headers, String jsonText) {
        RegisterRequestModel requestModel;
        LoginResponseModel responseModel;
        ObjectMapper mapper = new ObjectMapper();

        try {
            requestModel = mapper.readValue(jsonText, RegisterRequestModel.class);
        } catch (IOException e) {
            int resultCode;
            e.printStackTrace();
            if (e instanceof JsonParseException) {
                resultCode = -3;
                responseModel = new LoginResponseModel(resultCode, "JSON Parse Exception", null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (e instanceof JsonMappingException) {
                resultCode = -2;
                responseModel = new LoginResponseModel(resultCode, "JSON Mapping Exception", null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else {
                resultCode = -1;
                responseModel = new LoginResponseModel(resultCode, "Internal Server Error", null);
                ServiceLogger.LOGGER.severe("Internal Server Error");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
            }
        }

        try {
            ServiceLogger.LOGGER.info("Received request to login");
            ServiceLogger.LOGGER.info("Request:\n" + jsonText);

            String email = requestModel.getEmail();
            if (email == null || email.length() < 5 || email.length() > 128 /* a@b.c (5) is the mini length* 128 is db requirement */) {
                responseModel = new LoginResponseModel(-10, "Email address has invalid length.", null);
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }

            char [] password = requestModel.getPassword();
            if (password == null || password.length == 0) {
                responseModel = new LoginResponseModel(-12, "Password has invalid length.", null);
                ServiceLogger.LOGGER.info("Password has invalid length.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (password.length < 7 || password.length > 16) {
                responseModel = new LoginResponseModel(12, "Password does not meet length requirements.", null);
                ServiceLogger.LOGGER.info("Password does not meet length requirements.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            }

            Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+@(.+)\\.(.+)$", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(email);

            if (!matcher.matches()) {
                responseModel = new LoginResponseModel(-11, "Email address has invalid format.", null);
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }

            boolean hasUpper = false, hasLower = false, hasNum = false;
            for (char i: password) {
                if (Character.isLowerCase(i)) hasLower = true;
                if (Character.isUpperCase(i)) hasUpper = true;
                if (Character.isDigit(i)) hasNum = true;
            }
            if (!(hasLower && hasUpper && hasNum)) {
                responseModel = new LoginResponseModel(13, "Password does not meet character requirements.",null);
                ServiceLogger.LOGGER.info("Password does not meet character requirements.");
                return Response.status(Response.Status.OK).entity(responseModel).build();
            }

            Session newSession = Session.createSession(email);
            switch (RegisterInfo.authCheck(email, password)) {
                case 11:
                    responseModel = new LoginResponseModel(11, " Passwords do not match.",null);
                    ServiceLogger.LOGGER.info(" Passwords do not match.");
                    return Response.status(Response.Status.OK).entity(responseModel).build();
                case 14:
                    responseModel = new LoginResponseModel(14, "User not found.",null);
                    ServiceLogger.LOGGER.info("User not found.");
                    return Response.status(Response.Status.OK).entity(responseModel).build();
                default:
                    String Sid = RegisterInfo.loginSessionCheck(email, newSession);
                    if (!Sid.isEmpty()) responseModel = new LoginResponseModel(120, "User logged in successfully.", Sid);
                    else responseModel = new LoginResponseModel(120, "User logged in successfully.", newSession.getSessionID().toString());
                    ServiceLogger.LOGGER.info("User logged in successfully.");
                    return Response.status(Response.Status.OK).entity(responseModel).build();
            }

        } catch(Exception ee) {
            responseModel = new LoginResponseModel(-1, "500 Internal Server Error.",null);
            ServiceLogger.LOGGER.info("500 Internal Server Error.");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
        }
    }

    @Path("session")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response session(@Context HttpHeaders headers, String jsonText) {
        SessionRequestModel requestModel;
        SessionResponseModel responseModel;
        ObjectMapper mapper = new ObjectMapper();

        try {
            requestModel = mapper.readValue(jsonText, SessionRequestModel.class);
        } catch (IOException e) {
            int resultCode;
            e.printStackTrace();
            if (e instanceof JsonParseException) {
                resultCode = -3;
                responseModel = new SessionResponseModel(resultCode, "JSON Parse Exception", null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (e instanceof JsonMappingException) {
                resultCode = -2;
                responseModel = new SessionResponseModel(resultCode, "JSON Mapping Exception", null);
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else {
                resultCode = -1;
                responseModel = new SessionResponseModel(resultCode, "Internal Server Error", null);
                ServiceLogger.LOGGER.severe("Internal Server Error");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
            }
        }
        ServiceLogger.LOGGER.info("GET Session Request: " + jsonText);
        String session_id = requestModel.getSession_id();
        if (session_id.length() < 64 || session_id.length() > 128) {
            responseModel = new SessionResponseModel(-13, "Token has invalid length.",null);
            ServiceLogger.LOGGER.info("Token has invalid length.");
            return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
        }
        String email = requestModel.getEmail();
        if (email == null || email.length() < 5 || email.length() > 128 /* a@b.c (5) is the mini length* 128 is db requirement */) {
            responseModel = new SessionResponseModel(-10, "Email address has invalid length.",null);
            ServiceLogger.LOGGER.info("Email address has invalid length.");
            return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
        }

        Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+@(.+)\\.(.+)$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(email);

        if (!matcher.matches()) {
            responseModel = new SessionResponseModel(-11, "Email address has invalid format.",null);
            ServiceLogger.LOGGER.info("Email address has invalid format.");
            return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
        }
        if (!RegisterInfo.checkEmailExist(email)) {
            responseModel = new SessionResponseModel(14, "User not found.",null);
            ServiceLogger.LOGGER.info("User not found.");
            return Response.status(Response.Status.OK).entity(responseModel).build();
        }
        try {
//            String query1 = "UPDATE session\n" +
//                    "SET session.status = 3\n" +
//                    "WHERE session.expr_time < ?;";
            String query2 = "SELECT SS.status, S.session_id\n" +
                    "FROM session S INNER JOIN session_status SS ON S.status=SS.status_id\n" +
                    "WHERE S.email LIKE ?";
            PreparedStatement ps2 = IDMService.getCon().prepareStatement(query2);
//            PreparedStatement ps1 = IDMService.getCon().prepareStatement(query1);
//            ps1.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
//            ServiceLogger.LOGGER.info("UPDATE: " + ps1.toString());
//            ps1.executeUpdate();
            ps2.setString(1, email);
            ServiceLogger.LOGGER.info("SELECT: " + ps2.toString());
            ResultSet rs = ps2.executeQuery();
            responseModel = new SessionResponseModel(134, "Session is not found.", null);
            while (rs.next()) {
                String sid = rs.getString(2);
                String status = rs.getString(1);
//                System.out.println(status.equals("Expired") && sid.equals(session_id));
//                System.out.println(sid);
                if (!status.isEmpty()) {
                    if (status.equals("ACTIVE") && sid.equals(session_id)) responseModel = new SessionResponseModel(130, "Session is active.", sid);
                    else if (status.equals("EXPIRED") && sid.equals(session_id)) responseModel = new SessionResponseModel(131, "Session is expired.", null);
                    else if (status.equals("CLOSED") && sid.equals(session_id)) responseModel = new SessionResponseModel(132, "Session is closed.", null);
                    else if (status.equals("REVOKED") && sid.equals(session_id)) responseModel = new SessionResponseModel(133, "Session is revoked.", null);
//                    ServiceLogger.LOGGER.severe("OK Request: " + "status is " + status + " and " + responseModel.getMessage());
//                    return Response.status(Response.Status.OK).entity(responseModel).build();
                }
            }
            ServiceLogger.LOGGER.info("OK Requested: " + responseModel.getMessage());
            return Response.status(Response.Status.OK).entity(responseModel).build();
        } catch (SQLException e) {
            ServiceLogger.LOGGER.warning("Query failed: Unable to retrieve student records.");
            e.printStackTrace();
        }
        responseModel = new SessionResponseModel(134, "Session is not found.", null);
        ServiceLogger.LOGGER.severe("OK Request: " + responseModel.getMessage());
        return Response.status(Response.Status.OK).entity(responseModel).build();
    }




    @Path("privilege")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response Privilege(@Context HttpHeaders headers, String jsonText) {
        plevelRequestModel requestModel;
        RegisterResponseModel responseModel;

        ObjectMapper mapper = new ObjectMapper();

        try {
            requestModel = mapper.readValue(jsonText, plevelRequestModel.class);
        } catch (IOException e) {
            int resultCode;
            e.printStackTrace();
            if (e instanceof JsonParseException) {
                resultCode = -3;
                responseModel = new RegisterResponseModel(resultCode, "JSON Parse Exception");
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else if (e instanceof JsonMappingException) {
                resultCode = -2;
                responseModel = new RegisterResponseModel(resultCode, "JSON Mapping Exception");
                ServiceLogger.LOGGER.warning("Unable to map JSON to POJO");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            } else {
                resultCode = -1;
                responseModel = new RegisterResponseModel(resultCode, "Internal Server Error");
                ServiceLogger.LOGGER.severe("Internal Server Error");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
            }
        }

        ServiceLogger.LOGGER.info("Received request for privilege");
        ServiceLogger.LOGGER.info("Request:\n" + jsonText);

        try {
            Integer requestedPlevel = requestModel.getPlevel();
            if (requestedPlevel < 1 || requestedPlevel > 5) {
                responseModel = new RegisterResponseModel(-14, "Privilege level out of valid range.");
                ServiceLogger.LOGGER.info("Privilege level out of valid range.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }
            String email = requestModel.getEmail();
            if (email == null || email.length() < 5 || email.length() > 128 /* a@b.c (5) is the mini length* 128 is db requirement */) {
                responseModel = new RegisterResponseModel(-10, "Email address has invalid length.");
                ServiceLogger.LOGGER.info("Email address has invalid length.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }

            Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+@(.+)\\.(.+)$", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(email);

            if (!matcher.matches()) {
                responseModel = new RegisterResponseModel(-11, "Email address has invalid format.");
                ServiceLogger.LOGGER.info("Email address has invalid format.");
                return Response.status(Response.Status.BAD_REQUEST).entity(responseModel).build();
            }
            int plevel = RegisterInfo.getPlevel(email);
            if (plevel == 0) {
                ServiceLogger.LOGGER.info("User requested level is " + requestedPlevel);
                responseModel = new RegisterResponseModel(14, "User not found.");
                ServiceLogger.LOGGER.info("User not found.");
            } else {
                if (plevel <= requestedPlevel) {
                    ServiceLogger.LOGGER.info("User requested level is " + requestedPlevel + " ,but actual plevel is " + plevel);
                    responseModel = new RegisterResponseModel(140, "User has insufficient privilege level.");
                    ServiceLogger.LOGGER.info("User has sufficient privilege level.");
                } else {
                    ServiceLogger.LOGGER.info("User requested level is " + requestedPlevel + " ,and actual plevel is " + plevel);
                    responseModel = new RegisterResponseModel(141, "User doesn't has insufficient privilege level.");
                    ServiceLogger.LOGGER.info("User doesn't has insufficient privilege level.");
                }
            }
            return Response.status(Response.Status.OK).entity(responseModel).build();
        } catch (Exception e) {
            responseModel = new RegisterResponseModel(-1, "Internal Server Error");
            ServiceLogger.LOGGER.severe("Internal Server Error");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(responseModel).build();
        }
    }
}
