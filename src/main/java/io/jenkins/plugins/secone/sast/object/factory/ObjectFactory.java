package io.jenkins.plugins.secone.sast.object.factory;

import java.io.File;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class ObjectFactory {

	public HttpPost createHttpPost(String uri) {
		return new HttpPost(uri);
	}

	public CloseableHttpClient createHttpClient() {
		return HttpClients.custom().build();
	}

	public String getGitFolderConfigPath() {
		return ".git" + File.separator + "config";
	}
}
