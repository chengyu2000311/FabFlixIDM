package edu.uci.ics.hcheng10.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SessionRequestModel {
    @JsonProperty(value = "email", required = true)
    private String email;

    @JsonProperty(value = "session_id", required = true)
    private String session_id;

    @JsonCreator
    public SessionRequestModel(@JsonProperty(value = "email", required = true) String email,
                                @JsonProperty(value = "session_id", required = true) String session_id) {
        this.email = email;
        this.session_id = session_id;
    }

    @JsonProperty(value = "email", required = true)
    public String getEmail() {
        return email;
    }

    @JsonProperty(value = "session_id", required = true)
    public String getSession_id() {
        return session_id;
    }
}