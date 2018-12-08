namespace org.bouncycastle.mail.smime.examples
{


	public class ExampleUtils
	{
		/// <summary>
		/// Dump the content of the passed in BodyPart to the file fileName.
		/// </summary>
		/// <exception cref="MessagingException"> </exception>
		/// <exception cref="IOException"> </exception>
		public static void dumpContent(MimeBodyPart bodyPart, string fileName)
		{
			//
			// print mime type of compressed content
			//
			JavaSystem.@out.println("content type: " + bodyPart.getContentType());

			//
			// recover the compressed content
			//
			OutputStream @out = new FileOutputStream(fileName);
			InputStream @in = bodyPart.getInputStream();

			byte[] buf = new byte[10000];
			int len;

			while ((len = @in.read(buf, 0, buf.Length)) > 0)
			{
				@out.write(buf, 0, len);
			}

			@out.close();
		}

		public static string findKeyAlias(KeyStore store, string storeName, char[] password)
		{
			store.load(new FileInputStream(storeName), password);

			Enumeration e = store.aliases();
			string keyAlias = null;

			while (e.hasMoreElements())
			{
				string alias = (string)e.nextElement();

				if (store.isKeyEntry(alias))
				{
					keyAlias = alias;
				}
			}

			if (string.ReferenceEquals(keyAlias, null))
			{
				throw new IllegalArgumentException("can't find a private key in keyStore: " + storeName);
			}

			return keyAlias;
		}
	}

}