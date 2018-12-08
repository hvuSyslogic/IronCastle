using System;

namespace org.bouncycastle.mail.smime.handlers
{



	public class multipart_signed : DataContentHandler
	{
		private static readonly ActivationDataFlavor ADF = new ActivationDataFlavor(typeof(MimeMultipart), "multipart/signed", "Multipart Signed");
		private static readonly DataFlavor[] DFS = new DataFlavor[] {ADF};

		public virtual object getContent(DataSource ds)
		{
			try
			{
				return new MimeMultipart(ds);
			}
			catch (MessagingException)
			{
				return null;
			}
		}

		public virtual object getTransferData(DataFlavor df, DataSource ds)
		{
			if (ADF.Equals(df))
			{
				return getContent(ds);
			}
			else
			{
				return null;
			}
		}

		public virtual DataFlavor[] getTransferDataFlavors()
		{
			return DFS;
		}

		public virtual void writeTo(object obj, string _mimeType, OutputStream os)
		{

			if (obj is MimeMultipart)
			{
				try
				{
					outputBodyPart(os, obj);
				}
				catch (MessagingException ex)
				{
					throw new IOException(ex.Message);
				}
			}
			else if (obj is byte[])
			{
				os.write((byte[])obj);
			}
			else if (obj is InputStream)
			{
				int b;
				InputStream @in = (InputStream)obj;

				if (!(@in is BufferedInputStream))
				{
					@in = new BufferedInputStream(@in);
				}

				while ((b = @in.read()) >= 0)
				{
					os.write(b);
				}

				@in.close();
			}
			else if (obj is SMIMEStreamingProcessor)
			{
				SMIMEStreamingProcessor processor = (SMIMEStreamingProcessor)obj;

				processor.write(os);
			}
			else
			{
				throw new IOException("unknown object in writeTo " + obj);
			}
		}

		/*
		 * Output the mulitpart as a collection of leaves to make sure preamble text is not included.
		 */
		private void outputBodyPart(OutputStream @out, object bodyPart)
		{
			if (bodyPart is Multipart)
			{
				Multipart mp = (Multipart)bodyPart;
				ContentType contentType = new ContentType(mp.getContentType());
				string boundary = "--" + contentType.getParameter("boundary");

				LineOutputStream lOut = new LineOutputStream(@out);

				for (int i = 0; i < mp.getCount(); i++)
				{
					lOut.writeln(boundary);
					outputBodyPart(@out, mp.getBodyPart(i));
					lOut.writeln(); // CRLF terminator
				}

				lOut.writeln(boundary + "--");
				return;
			}

			MimeBodyPart mimePart = (MimeBodyPart)bodyPart;

			if (SMIMEUtil.isMultipartContent(mimePart))
			{
				object content = mimePart.getContent();

				if (content is Multipart)
				{
					Multipart mp = (Multipart)content;
					ContentType contentType = new ContentType(mp.getContentType());
					string boundary = "--" + contentType.getParameter("boundary");

					LineOutputStream lOut = new LineOutputStream(@out);

					Enumeration headers = mimePart.getAllHeaderLines();
					while (headers.hasMoreElements())
					{
						lOut.writeln((string)headers.nextElement());
					}

					lOut.writeln(); // CRLF separator

					outputPreamble(lOut, mimePart, boundary);

					outputBodyPart(@out, mp);
					return;
				}
			}

			mimePart.writeTo(@out);
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
				return; // no underlying content, rely on default generation
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

			if (ch < 0)
			{
				return null;
			}

			return b.ToString();
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
	}

}