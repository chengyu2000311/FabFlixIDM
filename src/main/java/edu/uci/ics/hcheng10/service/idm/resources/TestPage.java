package edu.uci.ics.hcheng10.service.idm.resources;

import edu.uci.ics.hcheng10.service.idm.logger.ServiceLogger;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

@Path("test") // Outer path
public class TestPage {
    @Path("hello") // This function's path
    @GET // Type of request
    @Produces(MediaType.APPLICATION_JSON)
    public Response helloWorld() {
        System.err.println("Hello world!");
        ServiceLogger.LOGGER.info("Hello!");
        return Response.status(Status.OK).build();
    }
}