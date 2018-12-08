namespace org.bouncycastle.crypto.test.cavp
{

	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using CMac = org.bouncycastle.crypto.macs.CMac;
	using HMac = org.bouncycastle.crypto.macs.HMac;

	public class CAVPReader
	{

		private static readonly Pattern COMMENT_PATTERN = Pattern.compile(@"^\s*\#\s*(.*)$");
		private static readonly Pattern CONFIG_PATTERN = Pattern.compile(@"^\s*+\[\s*+(.*?)\s*+=\s*+(.*?)\s*+\]\s*+$");
		private static readonly Pattern VECTOR_PATTERN = Pattern.compile(@"^\s*+(.*?)\s*+=\s*+(.*?)\s*+$");
		private static readonly Pattern EMPTY_PATTERN = Pattern.compile(@"^\s*+$");
		internal static readonly Pattern PATTERN_FOR_R = Pattern.compile(@"(\d+)_BITS");
		private readonly CAVPListener listener;
		private string name;
		private BufferedReader lineReader;


		public CAVPReader(CAVPListener listener)
		{
			this.listener = listener;
		}

		public virtual void setInput(string name, Reader reader)
		{
			this.name = name;
			this.lineReader = new BufferedReader(reader);
		}

		public virtual void readAll()
		{

			listener.setup();

			Properties config = new Properties();

			bool startNewVector = true;

			Properties vectors = new Properties();

			while (true)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String line = lineReader.readLine();
				string line = lineReader.readLine();
				if (string.ReferenceEquals(line, null))
				{
					listener.receiveEnd();
					break;
				}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.regex.Matcher commentMatcher = COMMENT_PATTERN.matcher(line);
				Matcher commentMatcher = COMMENT_PATTERN.matcher(line);
				if (commentMatcher.matches())
				{
					listener.receiveCommentLine(commentMatcher.group(1));
					continue;
				}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.regex.Matcher configMatcher = CONFIG_PATTERN.matcher(line);
				Matcher configMatcher = CONFIG_PATTERN.matcher(line);
				if (configMatcher.matches())
				{
					config.put(configMatcher.group(1), configMatcher.group(2));
					continue;
				}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.regex.Matcher vectorMatcher = VECTOR_PATTERN.matcher(line);
				Matcher vectorMatcher = VECTOR_PATTERN.matcher(line);
				if (vectorMatcher.matches())
				{
					vectors.put(vectorMatcher.group(1), vectorMatcher.group(2));
					startNewVector = false;
					continue;
				}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.regex.Matcher emptyMatcher = EMPTY_PATTERN.matcher(line);
				Matcher emptyMatcher = EMPTY_PATTERN.matcher(line);
				if (emptyMatcher.matches())
				{
					if (startNewVector)
					{
						continue;
					}

					listener.receiveCAVPVectors(name, config, vectors);
					vectors = new Properties();
					startNewVector = true;
				}
			}

			listener.tearDown();
		}

		internal static Mac createPRF(Properties config)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.Mac prf;
			Mac prf;
			if (config.getProperty("PRF").matches(@"CMAC_AES\d\d\d"))
			{
				BlockCipher blockCipher = new AESEngine();
				prf = new CMac(blockCipher);
			}
			else if (config.getProperty("PRF").matches(@"CMAC_TDES\d"))
			{
				BlockCipher blockCipher = new DESedeEngine();
				prf = new CMac(blockCipher);
			}
			else if (config.getProperty("PRF").matches("HMAC_SHA1"))
			{
				Digest digest = new SHA1Digest();
				prf = new HMac(digest);
			}
			else if (config.getProperty("PRF").matches("HMAC_SHA224"))
			{
				Digest digest = new SHA224Digest();
				prf = new HMac(digest);
			}
			else if (config.getProperty("PRF").matches("HMAC_SHA256"))
			{
				Digest digest = new SHA256Digest();
				prf = new HMac(digest);
			}
			else if (config.getProperty("PRF").matches("HMAC_SHA384"))
			{
				Digest digest = new SHA384Digest();
				prf = new HMac(digest);
			}
			else if (config.getProperty("PRF").matches("HMAC_SHA512"))
			{
				Digest digest = new SHA512Digest();
				prf = new HMac(digest);
			}
			else
			{
				throw new IllegalStateException("Unknown Mac for PRF");
			}
			return prf;
		}

	}

}