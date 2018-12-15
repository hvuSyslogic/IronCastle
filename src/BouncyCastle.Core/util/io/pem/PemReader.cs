using System;
using System.IO;
using BouncyCastle.Core.Port.java.io;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util.io.pem
{

	using Base64 = org.bouncycastle.util.encoders.Base64;

	/// <summary>
	/// A generic PEM reader, based on the format outlined in RFC 1421
	/// </summary>
	public class PemReader : BufferedReader
	{
		private const string BEGIN = "-----BEGIN ";
		private const string END = "-----END ";

		public PemReader(Reader reader) : base(reader)
		{
		}

		/// <summary>
		/// Read the next PEM object as a blob of raw data with header information.
		/// </summary>
		/// <returns> the next object in the stream, null if no objects left. </returns>
		/// <exception cref="IOException"> in case of a parse error. </exception>
		public virtual PemObject readPemObject()
		{
			string line = readLine();

			while (!string.ReferenceEquals(line, null) && !line.StartsWith(BEGIN, StringComparison.Ordinal))
			{
				line = readLine();
			}

			if (!string.ReferenceEquals(line, null))
			{
				line = line.Substring(BEGIN.Length);
				int index = line.IndexOf('-');
				string type = line.Substring(0, index);

				if (index > 0)
				{
					return loadObject(type);
				}
			}

			return null;
		}

		private PemObject loadObject(string type)
		{
			string line;
			string endMarker = END + type;
			StringBuffer buf = new StringBuffer();
			List headers = new ArrayList();

			while (!string.ReferenceEquals((line = readLine()), null))
			{
				if (line.IndexOf(":", StringComparison.Ordinal) >= 0)
				{
					int index = line.IndexOf(':');
					string hdr = line.Substring(0, index);
					string value = line.Substring(index + 1).Trim();

					headers.add(new PemHeader(hdr, value));

					continue;
				}

				if (line.IndexOf(endMarker, StringComparison.Ordinal) != -1)
				{
					break;
				}

				buf.append(line.Trim());
			}

			if (string.ReferenceEquals(line, null))
			{
				throw new IOException(endMarker + " not found");
			}

			return new PemObject(type, headers, Base64.decode(buf.ToString()));
		}

	}

}