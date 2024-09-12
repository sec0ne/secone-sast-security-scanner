package io.jenkins.plugins.secone.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URISyntaxException;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import com.cloudbees.plugins.credentials.CredentialsProvider;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import io.jenkins.plugins.secone.sast.SecOneSastScannerPlugin;
import io.jenkins.plugins.secone.sast.object.factory.ObjectFactory;
import io.jenkins.plugins.secone.sast.pojo.Threshold;
import jenkins.model.Jenkins;

@RunWith(MockitoJUnitRunner.class)
public class SecOneSastScannerPluginTest {

	@Mock
	private AbstractBuild<?, ?> abstractBuild;
	@Mock
	private Run<?, ?> run;
	@Mock
	private FilePath filePath;
	@Mock
	private Launcher launcher;
	@Mock
	private BuildListener buildListener;
	@Mock
	private TaskListener taskListener;
	@Mock
	private EnvVars envVars;
	@Mock
	private Jenkins jenkins;
	@Mock
	private HttpEntity httpEntity;

	@Mock
	private HttpEntity statusHttpEntity;
	@Mock
	private ObjectFactory objectFactory;

	private SecOneSastScannerPlugin plugin;
	private static MockedStatic<Jenkins> mockedJenkins;
	private static MockedStatic<CredentialsProvider> mockedCredentialsProvider;
	private static String WORKSPACE_DIRECTORY_LOCATION;
	private static InputStream sampleReportStream;
	private static InputStream sampleInitiateScanResponseStream;

	@Before
	public void setUp() throws URISyntaxException, IOException {
		WORKSPACE_DIRECTORY_LOCATION = new File("src/test/resources/test-data").getAbsolutePath();
		sampleReportStream = new FileInputStream(WORKSPACE_DIRECTORY_LOCATION + "/sampleapp-report.txt");
		sampleInitiateScanResponseStream = new FileInputStream(
				WORKSPACE_DIRECTORY_LOCATION + "/sample-initiate-scan-response.txt");
		plugin = new SecOneSastScannerPlugin("customCredentialsId", objectFactory);
		when(taskListener.getLogger()).thenReturn(mock(PrintStream.class));
		mockJenkkins();
	}

	@After
	public void close() {
		mockedJenkins.close();
		mockedCredentialsProvider.close();
	}

	@Test
	public void testScanFromUI() throws Exception {
		prepareScanSetup();
		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScanWithThresholdMediumThreshold() throws Exception {
		plugin.setApplyThreshold(true);
		prepareScanSetup();
		Threshold threshold = new Threshold("100", "100", "0", "", "fail");
		plugin.setThreshold(threshold);
		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test(expected = AbortException.class)
	public void testScanWithThresholdWhereStatusActionIsFail() throws Exception {
		plugin.setApplyThreshold(true);
		prepareScanSetup();
		Threshold threshold = new Threshold("0", "10", "", "", "fail");
		plugin.setThreshold(threshold);
		plugin.perform(abstractBuild, launcher, buildListener);
	}

	@Test
	public void testScanWithThresholdWhereStatusActionIsUnstable() throws Exception {
		plugin.setApplyThreshold(true);
		prepareScanSetup();
		Threshold threshold = new Threshold("0", "10", "", "", "unstable");
		plugin.setThreshold(threshold);
		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScanWithThresholdWhereStatusActionIsContinue() throws Exception {
		plugin.setApplyThreshold(true);
		prepareScanSetup();
		Threshold threshold = new Threshold("0", "10", "", "", "continue");
		plugin.setThreshold(threshold);
		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test(expected = AbortException.class)
	public void testInvalidScmUrl() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");
		mockApiKeyJourney("customCredentialsId");
		plugin.perform(abstractBuild, launcher, buildListener);
	}

	@Test(expected = AbortException.class)
	public void testScanFromUIException() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);
		plugin.perform(abstractBuild, launcher, buildListener);
	}

	@Test(expected = AbortException.class)
	public void testPerformFromScriptException() throws Exception {
		plugin.perform(run, filePath, envVars, launcher, taskListener);
	}

	@Test
	public void testGetApiKey() throws Exception {
		when(CredentialsProvider.findCredentialById(anyString(), eq(StringCredentials.class), eq(run), anyList()))
				.thenReturn(null);
		mockApiKeyJourney("SEC1_API_KEY");
		assertEquals("testApiKey", plugin.getApiKey(run, taskListener));
	}

	@Test
	public void testGetApiKeyWithCustomCredentialsId() throws Exception {
		plugin.setApiCredentialsId("customCredentialsId");
		mockApiKeyJourney("customCredentialsId");
		assertEquals("testApiKey", plugin.getApiKey(run, taskListener));
	}

	@Test
	public void testGetApiKeyWithNoCredentials() throws Exception {
		when(CredentialsProvider.findCredentialById(anyString(), eq(StringCredentials.class), eq(run), anyList()))
				.thenReturn(null);
		assertNull(plugin.getApiKey(run, taskListener));
	}

	@Test
	public void testGetGitUrl() throws Exception {
		String gitConfig = "[remote \"origin\"]\n\turl = https://github.com/user/repo.git\n";
		File gitDir = new File(WORKSPACE_DIRECTORY_LOCATION, ".git");
		gitDir.mkdirs();
		File configFile = new File(gitDir, "config");
		org.apache.commons.io.FileUtils.writeStringToFile(configFile, gitConfig, "UTF-8");
		when(objectFactory.getGitFolderConfigPath()).thenReturn("config");
		String gitUrl = plugin.getGitUrl(WORKSPACE_DIRECTORY_LOCATION);
		assertEquals("https://github.com/MOCK-Test/sampleapp", gitUrl);

		org.apache.commons.io.FileUtils.deleteDirectory(gitDir);
	}

	@Test
	public void testGetGitBranch() throws Exception {
		String headContent = "ref: refs/heads/main";
		File gitDir = new File(WORKSPACE_DIRECTORY_LOCATION, ".git");
		gitDir.mkdirs();
		File headFile = new File(gitDir, "HEAD");
		org.apache.commons.io.FileUtils.writeStringToFile(headFile, headContent, "UTF-8");

		String branch = plugin.getGitBranch(WORKSPACE_DIRECTORY_LOCATION);
		assertEquals("main", branch);

		org.apache.commons.io.FileUtils.deleteDirectory(gitDir);
	}

	@Test
	public void testRemoveCredentialsFromGitUrl() throws Exception {
		String rawUrl = "https://username:password@github.com/user/repo.git";
		String cleanUrl = plugin.removeCredentialsFromGitUrl(rawUrl);
		assertEquals("https://github.com/user/repo.git", cleanUrl);
	}

	private void prepareScanSetup() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");
		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);

		mockApiKeyJourney("customCredentialsId");

		HttpPost httpPost = mock(HttpPost.class);
		when(objectFactory.createHttpPost(anyString())).thenReturn(httpPost);

		CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse statusResponse = mock(CloseableHttpResponse.class);
		CloseableHttpClient client = mock(CloseableHttpClient.class);
		when(objectFactory.createHttpClient()).thenReturn(client);
		// when(client.execute(httpPost)).thenReturn(httpResponse);

		when(client.execute(any(HttpPost.class))).thenReturn(httpResponse).thenReturn(statusResponse);

		StatusLine statusLine = mock(StatusLine.class);
		when(httpResponse.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(200);

		when(httpResponse.getEntity()).thenReturn(httpEntity);
		when(statusResponse.getEntity()).thenReturn(statusHttpEntity);

		when(httpEntity.getContent()).thenReturn(sampleInitiateScanResponseStream);
		when(statusHttpEntity.getContent()).thenReturn(sampleReportStream);

		when(objectFactory.getGitFolderConfigPath()).thenReturn("config");
	}

	private void mockApiKeyJourney(String keyID) {
		StringCredentials apiKeyCred = mock(StringCredentials.class);
		when(CredentialsProvider.findCredentialById(eq(keyID), eq(StringCredentials.class), any(Run.class), anyList()))
				.thenReturn(apiKeyCred);
		Secret mysecret = mock(Secret.class);
		when(apiKeyCred.getSecret()).thenReturn(mysecret);
		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");
	}

	private void mockJenkkins() {
		mockedJenkins = mockStatic(Jenkins.class);
		when(Jenkins.get()).thenReturn(jenkins);
		mockedCredentialsProvider = mockStatic(CredentialsProvider.class);
	}
}