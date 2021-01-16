package edu.uci.ics.hcheng10.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponseModel {
    @JsonProperty(value = "resultCode", required = true)
    private int resultCode;

    @JsonProperty(value = "message", required = true)
    private String message;

    @JsonProperty(value = "session_id")
    private String session_id;

    @JsonCreator
    public LoginResponseModel(int resultCode, String message, String session_id) {
        this.resultCode = resultCode;
        this.message = message;
        this.session_id = session_id;
    }

    @JsonProperty("resultCode")
    public int getResultCode() {
        return resultCode;
    }

    @JsonProperty("message")
    public String getMessage() {
        return message;
    }

    @JsonProperty("session_id")
    public String getSession_id() {
        return session_id;
    }
}
