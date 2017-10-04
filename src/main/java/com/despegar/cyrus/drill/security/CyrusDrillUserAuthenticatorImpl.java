package com.despegar.cyrus.drill.security;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.drill.common.config.DrillConfig;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticator;
import org.apache.drill.exec.rpc.user.security.UserAuthenticationException;
import org.apache.drill.exec.rpc.user.security.UserAuthenticatorTemplate;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;


@UserAuthenticatorTemplate(type = "cyrusCustomAuthenticatorType")
public class CyrusDrillUserAuthenticatorImpl implements UserAuthenticator{

    private JsonObject jsonObject;
    private static String USERS_KEY = "drillUsers";

    /**
     * Setup for authenticating user credentials.
     */
    public void setup(DrillConfig drillConfig) throws DrillbitStartupException {
        // If the authenticator has any setup such as making sure authenticator provider servers are up and running or
        // needed libraries are available, it should be added here.

        String pathName = "/home/despegar/sensitive.conf";

        String maybe = null;

        try {

            List<String> lines = Files.readAllLines(Paths.get(pathName), Charset.defaultCharset());

            for(String line : lines){
                if(line.startsWith(USERS_KEY)){
                    maybe = line;
                    break;
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
            throw new DrillbitStartupException(e);
        }

        if(maybe == null)
            throw new DrillbitStartupException(String.format("No '%s' property is present.",USERS_KEY));

        String substring = maybe.substring(USERS_KEY.length() + 1);

        this.jsonObject = new JsonParser().parse(substring).getAsJsonObject();
    }

    /**
     * Authenticate the given <i>user</i> and <i>password</i> combination.
     *
     * @param userName
     * @param password
     * @throws UserAuthenticationException if authentication fails for given user and password.
     */
    public void authenticate(String userName, String password) throws UserAuthenticationException {

        if(!this.jsonObject.has(userName))
            throw new UserAuthenticationException("User does not exists.");

        if(!this.jsonObject.get(userName).getAsString().equals(password))
            throw new UserAuthenticationException("User/Password is incorrect.");


    }

    /**
     * Close the authenticator. Used to release resources. Ex. LDAP authenticator opens connections to LDAP server,
     * such connections resources are released in a safe manner as part of close.
     *
     * @throws IOException
     */
    public void close() throws IOException {

    }
}
