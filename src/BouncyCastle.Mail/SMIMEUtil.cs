using System;

namespace org.bouncycastle.mail.smime
{


	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using CMSTypedStream = org.bouncycastle.cms.CMSTypedStream;
	using CRLFOutputStream = org.bouncycastle.mail.smime.util.CRLFOutputStream;
	using FileBackedMimeBodyPart = org.bouncycastle.mail.smime.util.FileBackedMimeBodyPart;
	using Strings = org.bouncycastle.util.Strings;

	public class SMIMEUtil
	{
		private const string MULTIPART = "multipart";
		private const int BUF_SIZE = 32760;

		public static bool isMultipartContent(Part part)
		{
			string partType = Strings.toLowerCase(part.getContentType());

			return partType.StartsWith(MULTIPART, StringComparison.Ordinal);
		}

		internal static bool isCanonicalisationRequired(MimeBodyPart bodyPart, string defaultContentTransferEncoding)
		{
			string[] cte = bodyPart.getHeader("Content-Transfer-Encoding");
			string contentTransferEncoding;

			if (cte == null)
			{
				contentTransferEncoding = defaultContentTransferEncoding;
			}
			else
			{
				contentTransferEncoding = cte[0];
			}

			return !contentTransferEncoding.Equals("binary", StringComparison.OrdinalIgnoreCase);
		}

		public class LineOutputStream : FilterOutputStream
		{
			internal static byte[] newline;

			public LineOutputStream(OutputStream outputstream) : base(outputstream)
			{
			}

			public virtual void writeln(string s)
			{
				try
				{
					byte[] abyte0 = getBytes(s);
					base.@out.write(abyte0);
					base.@out.write(newline);
				}
				catch (Exception exception)
				{
					throw new MessagingException("IOException", exception);
				}
			}

			public virtual void writeln()
			{
				try
				{
					base.@out.write(newline);
				}
				catch (Exception exception)
				{
					throw new MessagingException("IOException", exception);
				}
			}

			static LineOutputStream()
			{
				newline = new byte[2];
				newline[0] = 13;
				newline[1] = 10;
			}

			internal static byte[] getBytes(string s)
			{
				char[] ac = s.ToCharArray();
				int i = ac.Length;
				byte[] abyte0 = new byte[i];
				int j = 0;

				while (j < i)
				{
					abyte0[j] = (byte)ac[j++];
				}

				return abyte0;
			}
		}

		/// <summary>
		/// internal preamble is generally included in signatures, while this is technically wrong,
		/// if we find internal preamble we include it by default.
		/// </summary>
		internal static void outputPreamble(LineOutputStream lOut, MimeBodyPart part, string boundary)
		{
			InputStream @in;

			try
			{
				@in = part.getRawInputStream();
			}
			catch (MessagingException)
			{
				return; // no underlying content rely on default generation
			}

			string line;

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.Equals(boundary))
				{
					break;
				}

				lOut.writeln(line);
			}

			@in.close();

			if (string.ReferenceEquals(line, null))
			{
				throw new MessagingException("no boundary found");
			}
		}

		/// <summary>
		/// internal postamble is generally included in signatures, while this is technically wrong,
		/// if we find internal postamble we include it by default.
		/// </summary>
		internal static void outputPostamble(LineOutputStream lOut, MimeBodyPart part, int count, string boundary)
		{
			InputStream @in;

			try
			{
				@in = part.getRawInputStream();
			}
			catch (MessagingException)
			{
				return; // no underlying content rely on default generation
			}

			string line;
			int boundaries = count + 1;

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(boundary, StringComparison.Ordinal))
				{
					boundaries--;

					if (boundaries == 0)
					{
						break;
					}
				}
			}

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				lOut.writeln(line);
			}

			@in.close();

			if (boundaries != 0)
			{
				throw new MessagingException("all boundaries not found for: " + boundary);
			}
		}

		internal static void outputPostamble(LineOutputStream lOut, BodyPart parent, string parentBoundary, BodyPart part)
		{
			InputStream @in;

			try
			{
				@in = ((MimeBodyPart)parent).getRawInputStream();
			}
			catch (MessagingException)
			{
				return; // no underlying content rely on default generation
			}


			MimeMultipart multipart = (MimeMultipart)part.getContent();
			ContentType contentType = new ContentType(multipart.getContentType());
			string boundary = "--" + contentType.getParameter("boundary");
			int count = multipart.getCount() + 1;
			string line;
			while (count != 0 && !string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(boundary, StringComparison.Ordinal))
				{
					count--;
				}
			}

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(parentBoundary, StringComparison.Ordinal))
				{
					break;
				}
				lOut.writeln(line);
			}

			@in.close();
		}

		/*
		 * read a line of input stripping of the tailing \r\n
		 */
		private static string readLine(InputStream @in)
		{
			StringBuffer b = new StringBuffer();

			int ch;
			while ((ch = @in.read()) >= 0 && ch != '\n')
			{
				if (ch != '\r')
				{
					b.append((char)ch);
				}
			}

			if (ch < 0 && b.length() == 0)
			{
				return null;
			}

			return b.ToString();
		}

		internal static void outputBodyPart(OutputStream @out, bool topLevel, BodyPart bodyPart, string defaultContentTransferEncoding)
		{
			if (bodyPart is MimeBodyPart)
			{
				MimeBodyPart mimePart = (MimeBodyPart)bodyPart;
				string[] cte = mimePart.getHeader("Content-Transfer-Encoding");
				string contentTransferEncoding;

				if (isMultipartContent(mimePart))
				{
					object content = bodyPart.getContent();
					Multipart mp;
					if (content is Multipart)
					{
						mp = (Multipart)content;
					}
					else
					{
						mp = new MimeMultipart(bodyPart.getDataHandler().getDataSource());
					}

					ContentType contentType = new ContentType(mp.getContentType());
					string boundary = "--" + contentType.getParameter("boundary");

					SMIMEUtil.LineOutputStream lOut = new SMIMEUtil.LineOutputStream(@out);

					Enumeration headers = mimePart.getAllHeaderLines();
					while (headers.hasMoreElements())
					{
						string header = (string)headers.nextElement();
						lOut.writeln(header);
					}

					lOut.writeln(); // CRLF separator

					outputPreamble(lOut, mimePart, boundary);

					for (int i = 0; i < mp.getCount(); i++)
					{
						lOut.writeln(boundary);
						BodyPart part = mp.getBodyPart(i);
						outputBodyPart(@out, false, part, defaultContentTransferEncoding);
						if (!isMultipartContent(part))
						{
							lOut.writeln(); // CRLF terminator needed
						}
						else
						{ // output nested preamble
							outputPostamble(lOut, mimePart, boundary, part);
						}
					}

					lOut.writeln(boundary + "--");

					if (topLevel)
					{
						outputPostamble(lOut, mimePart, mp.getCount(), boundary);
					}

					return;
				}

				if (cte == null)
				{
					contentTransferEncoding = defaultContentTransferEncoding;
				}
				else
				{
					contentTransferEncoding = cte[0];
				}

				if (!contentTransferEncoding.Equals("base64", StringComparison.OrdinalIgnoreCase) && !contentTransferEncoding.Equals("quoted-printable", StringComparison.OrdinalIgnoreCase))
				{
					if (!contentTransferEncoding.Equals("binary", StringComparison.OrdinalIgnoreCase))
					{
						@out = new CRLFOutputStream(@out);
					}
					bodyPart.writeTo(@out);
					@out.flush();
					return;
				}

				bool base64 = contentTransferEncoding.Equals("base64", StringComparison.OrdinalIgnoreCase);

				//
				// Write raw content, performing canonicalization
				//
				InputStream inRaw;

				try
				{
					inRaw = mimePart.getRawInputStream();
				}
				catch (MessagingException)
				{
					// this is less than ideal, but if the raw output stream is unavailable it's the
					// best option we've got.
					@out = new CRLFOutputStream(@out);
					bodyPart.writeTo(@out);
					@out.flush();
					return;
				}

				//
				// Write headers
				//
				LineOutputStream outLine = new LineOutputStream(@out);
				for (Enumeration e = mimePart.getAllHeaderLines(); e.hasMoreElements();)
				{
					string header = (string)e.nextElement();

					outLine.writeln(header);
				}

				outLine.writeln();
				outLine.flush();


				OutputStream outCRLF;

				if (base64)
				{
					outCRLF = new Base64CRLFOutputStream(@out);
				}
				else
				{
					outCRLF = new CRLFOutputStream(@out);
				}

				byte[] buf = new byte[BUF_SIZE];

				int len;
				while ((len = inRaw.read(buf, 0, buf.Length)) > 0)
				{

					outCRLF.write(buf, 0, len);
				}

				inRaw.close();

				outCRLF.flush();
			}
			else
			{
				if (!defaultContentTransferEncoding.Equals("binary", StringComparison.OrdinalIgnoreCase))
				{
					@out = new CRLFOutputStream(@out);
				}

				bodyPart.writeTo(@out);

				@out.flush();
			}
		}

		/// <summary>
		/// return the MimeBodyPart described in the raw bytes provided in content
		/// </summary>
		public static MimeBodyPart toMimeBodyPart(byte[] content)
		{
			return toMimeBodyPart(new ByteArrayInputStream(content));
		}

		/// <summary>
		/// return the MimeBodyPart described in the input stream content
		/// </summary>
		public static MimeBodyPart toMimeBodyPart(InputStream content)
		{
			try
			{
				return new MimeBodyPart(content);
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception creating body part.", e);
			}
		}

		internal static FileBackedMimeBodyPart toWriteOnceBodyPart(CMSTypedStream content)
		{
			try
			{
				return new WriteOnceFileBackedMimeBodyPart(content.getContentStream(), File.createTempFile("bcMail", ".mime"));
			}
			catch (IOException e)
			{
				throw new SMIMEException("IOException creating tmp file:" + e.Message, e);
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("can't create part: " + e, e);
			}
		}

		/// <summary>
		/// return a file backed MimeBodyPart described in <seealso cref="CMSTypedStream"/> content.
		/// </summary>
		public static FileBackedMimeBodyPart toMimeBodyPart(CMSTypedStream content)
		{
			try
			{
				return toMimeBodyPart(content, File.createTempFile("bcMail", ".mime"));
			}
			catch (IOException e)
			{
				throw new SMIMEException("IOException creating tmp file:" + e.Message, e);
			}
		}

		/// <summary>
		/// Return a file based MimeBodyPart represented by content and backed
		/// by the file represented by file.
		/// </summary>
		/// <param name="content"> content stream containing body part. </param>
		/// <param name="file"> file to store the decoded body part in. </param>
		/// <returns> the decoded body part. </returns>
		/// <exception cref="SMIMEException"> </exception>
		public static FileBackedMimeBodyPart toMimeBodyPart(CMSTypedStream content, File file)
		{
			try
			{
				return new FileBackedMimeBodyPart(content.getContentStream(), file);
			}
			catch (IOException e)
			{
				throw new SMIMEException("can't save content to file: " + e, e);
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("can't create part: " + e, e);
			}
		}

		/// <summary>
		/// Return a CMS IssuerAndSerialNumber structure for the passed in X.509 certificate.
		/// </summary>
		/// <param name="cert"> the X.509 certificate to get the issuer and serial number for. </param>
		/// <returns> an IssuerAndSerialNumber structure representing the certificate. </returns>
		public static IssuerAndSerialNumber createIssuerAndSerialNumberFor(X509Certificate cert)
		{
			try
			{
				return new IssuerAndSerialNumber((new JcaX509CertificateHolder(cert)).getIssuer(), cert.getSerialNumber());
			}
			catch (Exception e)
			{
				throw new CertificateParsingException("exception extracting issuer and serial number: " + e);
			}
		}

		public class WriteOnceFileBackedMimeBodyPart : FileBackedMimeBodyPart
		{
			public WriteOnceFileBackedMimeBodyPart(InputStream content, File file) : base(content, file)
			{
			}

			public override void writeTo(OutputStream @out)
			{
				base.writeTo(@out);

				this.dispose();
			}
		}

		public class Base64CRLFOutputStream : FilterOutputStream
		{
			protected internal int lastb;
			protected internal static byte[] newline;
			internal bool isCrlfStream;

			public Base64CRLFOutputStream(OutputStream outputstream) : base(outputstream)
			{
				lastb = -1;
			}

			public virtual void write(int i)
			{
				if (i == '\r')
				{
					@out.write(newline);
				}
				else if (i == '\n')
				{
					if (lastb != '\r')
					{ // imagine my joy...
						if (!(isCrlfStream && lastb == '\n'))
						{
							@out.write(newline);
						}
					}
					else
					{
						isCrlfStream = true;
					}
				}
				else
				{
					@out.write(i);
				}

				lastb = i;
			}

			public virtual void write(byte[] buf)
			{
				this.write(buf, 0, buf.Length);
			}

			public virtual void write(byte[] buf, int off, int len)
			{
				for (int i = off; i != off + len; i++)
				{
					this.write(buf[i]);
				}
			}

			public virtual void writeln()
			{
				base.@out.write(newline);
			}

			static Base64CRLFOutputStream()
			{
				newline = new byte[2];
				newline[0] = (byte)'\r';
				newline[1] = (byte)'\n';
			}
		}
	}

}