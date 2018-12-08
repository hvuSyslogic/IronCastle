namespace org.bouncycastle.mail.smime.util
{

	public class FileBackedMimeBodyPart : MimeBodyPart
	{
		private const int BUF_SIZE = 32760;

		private readonly File _file;

		/// <summary>
		/// Create a MimeBodyPart backed by the data in file.
		/// </summary>
		/// <param name="file"> file containing the body part. </param>
		/// <exception cref="MessagingException"> an exception occurs parsing file. </exception>
		/// <exception cref="IOException"> an exception occurs accessing file. </exception>
		public FileBackedMimeBodyPart(File file) : base(new SharedFileInputStream(file))
		{

			_file = file;
		}

		/// <summary>
		/// Create a MimeBodyPart backed by file based on the headers and
		/// content data in content.
		/// </summary>
		/// <param name="content"> an inputstream containing the body part. </param>
		/// <param name="file"> a handle to the backing file to use for storage. </param>
		/// <exception cref="MessagingException"> an exception occurs parsing the resulting body part in file. </exception>
		/// <exception cref="IOException"> an exception occurs accessing file or content. </exception>
		public FileBackedMimeBodyPart(InputStream content, File file) : this(saveStreamToFile(content, file))
		{
		}

		/// <summary>
		/// Create a MimeBodyPart backed by file, with the headers
		/// given in headers and body content taken from the stream body.
		/// </summary>
		/// <param name="headers"> headers for the body part. </param>
		/// <param name="body"> internal content for the body part. </param>
		/// <param name="file"> backing file to use.
		/// </param>
		/// <exception cref="MessagingException"> if the body part can't be produced. </exception>
		/// <exception cref="IOException"> if there is an issue reading stream or writing to file. </exception>
		public FileBackedMimeBodyPart(InternetHeaders headers, InputStream body, File file) : this(saveStreamToFile(headers, body, file))
		{
		}

		public virtual void writeTo(OutputStream @out)
		{
			if (!_file.exists())
			{
				throw new IOException("file " + _file.getCanonicalPath() + " no longer exists.");
			}

			base.writeTo(@out);
		}

		/// <summary>
		/// Close off the underlying shared streams and remove the backing file.
		/// </summary>
		/// <exception cref="IOException"> if streams cannot be closed or the file cannot be deleted. </exception>
		public virtual void dispose()
		{
			((SharedFileInputStream)contentStream).getRoot().dispose();

			if (_file.exists() && !_file.delete())
			{
				throw new IOException("deletion of underlying file <" + _file.getCanonicalPath() + "> failed.");
			}
		}

		private static File saveStreamToFile(InputStream content, File tempFile)
		{
			saveContentToStream(new FileOutputStream(tempFile), content);

			return tempFile;
		}

		private static File saveStreamToFile(InternetHeaders headers, InputStream content, File tempFile)
		{
			OutputStream @out = new FileOutputStream(tempFile);
			Enumeration en = headers.getAllHeaderLines();

			while (en.hasMoreElements())
			{
				writeHeader(@out, (string)en.nextElement());
			}

			writeSeperator(@out);

			saveContentToStream(@out, content);

			return tempFile;
		}


		private static void writeHeader(OutputStream @out, string header)
		{
			for (int i = 0; i != header.Length; i++)
			{
				@out.write(header[i]);
			}

			writeSeperator(@out);
		}

		 private static void writeSeperator(OutputStream @out)
		 {
			 @out.write('\r');
			 @out.write('\n');
		 }

		 private static void saveContentToStream(OutputStream @out, InputStream content)
		 {
			byte[] buf = new byte[BUF_SIZE];
			int len;

			while ((len = content.read(buf, 0, buf.Length)) > 0)
			{
				@out.write(buf, 0, len);
			}

			@out.close();
			content.close();
		 }
	}

}