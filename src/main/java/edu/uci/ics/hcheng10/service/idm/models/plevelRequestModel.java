package edu.uci.ics.hcheng10.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class plevelRequestModel {
    @JsonProperty(value = "email", required = true)
    private String email;

    @JsonProperty(value = "plevel", required = true)
    private Integer plevel;


    @JsonCreator
    void RegisterResponseModel(@JsonProperty(value = "email", required = true) String email,
                               @JsonProperty(value = "plevel", required = true) Integer plevel) {
        this.email = email;
        this.plevel = plevel;
    }

    @JsonProperty(value = "email", required = true)
    public String getEmail() {
        return email;
    }

    @JsonProperty(value = "plevel", required = true)
    public Integer getPlevel() {
        return plevel;
    }
}
