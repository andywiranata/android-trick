package com.andywiranata.provider.util;

import android.content.Context;
import android.content.SharedPreferences;


import com.andywiranata.provider.BuildConfig;
import com.andywiranata.provider.data.DataManager;
import com.andywiranata.provider.data.local.PreferencesHelper;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import okhttp3.Authenticator;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.Route;
import timber.log.Timber;

/**
 * Created by andywiranatawijaya on 5/18/16.
 */
public class TokenAuthenticator implements Authenticator {
    private static final String MEDIA_TYPE          =   "application/x-www-form-urlencoded";
    private static final String FORM_REQUEST_BODY   =   "grant_type=refresh_token&refresh_token=";
    private static final String URL_REFRESH_TOKEN   =   BuildConfig.URL + "/oauth/token?";

    private Context mContext;
    SharedPreferences mpref;

    public TokenAuthenticator(Context mContext) {
        this.mContext = mContext;
    }

    @Override
    public Request authenticate(Route route, Response response) throws IOException {

        if(response.request().header("Authorization") == null){
            Timber.i("authorization not found.");
            throw new IOException("Unexpected code " + response);
        }
        Timber.i("oops, your session is invalid, starting to refresh token");
        Timber.d("---- Start refresh token ----");
        mpref = mContext.getSharedPreferences(PreferencesHelper.PREF_FILE_NAME, Context.MODE_PRIVATE);

        final OkHttpClient client = new OkHttpClient();
        String oldRefreshToken = mpref.getString(DataManager.refreshToken_, "");
        MediaType mediaType = MediaType.parse(MEDIA_TYPE);

        RequestBody body = RequestBody.create(mediaType,
                FORM_REQUEST_BODY + oldRefreshToken);
        Request request = new Request.Builder()
                .url(URL_REFRESH_TOKEN)
                .post(body)
                .addHeader("authorization",BuildConfig.AUTH_TOKEN)
                .addHeader("cache-control", "no-cache")
                .addHeader("content-type", MEDIA_TYPE)
                .build();

        Response resp = client.newCall(request).execute();
        if (!resp.isSuccessful())
            throw new IOException(response.code()+"");

        String jsonData = resp.body().string();
        String newAccessToken   = null;
        String newRefreshToken  = null;
        String newTokenType     = null;


        try {
            JSONObject jsonObject = new JSONObject(jsonData);
            newAccessToken  =   jsonObject.getString("access_token");
            newRefreshToken =   jsonObject.getString("refresh_token");
            newTokenType    =   jsonObject.getString("token_type");

            setString(DataManager.accessToken_      , newAccessToken);
            setString(DataManager.refreshToken_     , newRefreshToken);
            setString(DataManager.tokenType_        , newTokenType);


        } catch (JSONException e) {
            throw new IOException("Unexpected code " + e);
        }
        return response.request().newBuilder()
                .header("Authorization", newTokenType+" "+newAccessToken)
                .build();
    }


    public void setString(String key, String value){
        SharedPreferences.Editor editor = mpref.edit();
        editor.putString(key, value);
        editor.commit();
    }
}
