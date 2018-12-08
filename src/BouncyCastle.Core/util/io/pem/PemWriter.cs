namespace org.bouncycastle.util.io.pem
{

	using Base64 = org.bouncycastle.util.encoders.Base64;

	/// <summary>
	/// A generic PEM writer, based on RFC 1421
	/// </summary>
	public class PemWriter : BufferedWriter
	{
		private const int LINE_LENGTH = 64;

		private readonly int nlLength;
		private char[] buf = new char[LINE_LENGTH];

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="out"> output stream to use. </param>
		public PemWriter(Writer @out) : base(@out)
		{

			string nl = Strings.lineSeparator();
			if (!string.ReferenceEquals(nl, null))
			{
				nlLength = nl.Length;
			}
			else
			{
				nlLength = 2;
			}
		}

		/// <summary>
		/// Return the number of bytes or characters required to contain the
		/// passed in object if it is PEM encoded.
		/// </summary>
		/// <param name="obj"> pem object to be output </param>
		/// <returns> an estimate of the number of bytes </returns>
		public virtual int getOutputSize(PemObject obj)
		{
			// BEGIN and END boundaries.
			int size = (2 * (obj.getType().Length + 10 + nlLength)) + 6 + 4;

			if (!obj.getHeaders().isEmpty())
			{
				for (Iterator it = obj.getHeaders().iterator(); it.hasNext();)
				{
					PemHeader hdr = (PemHeader)it.next();

					size += hdr.getName().Length + ": ".Length + hdr.getValue().Length + nlLength;
				}

				size += nlLength;
			}

			// base64 encoding
			int dataLen = ((obj.getContent().Length + 2) / 3) * 4;

			size += dataLen + (((dataLen + LINE_LENGTH - 1) / LINE_LENGTH) * nlLength);

			return size;
		}

		public virtual void writeObject(PemObjectGenerator objGen)
		{
			PemObject obj = objGen.generate();

			writePreEncapsulationBoundary(obj.getType());

			if (!obj.getHeaders().isEmpty())
			{
				for (Iterator it = obj.getHeaders().iterator(); it.hasNext();)
				{
					PemHeader hdr = (PemHeader)it.next();

					this.write(hdr.getName());
					this.write(": ");
					this.write(hdr.getValue());
					this.newLine();
				}

				this.newLine();
			}

			writeEncoded(obj.getContent());
			writePostEncapsulationBoundary(obj.getType());
		}

		private void writeEncoded(byte[] bytes)
		{
			bytes = Base64.encode(bytes);

			for (int i = 0; i < bytes.Length; i += buf.Length)
			{
				int index = 0;

				while (index != buf.Length)
				{
					if ((i + index) >= bytes.Length)
					{
						break;
					}
					buf[index] = (char)bytes[i + index];
					index++;
				}
				this.write(buf, 0, index);
				this.newLine();
			}
		}

		private void writePreEncapsulationBoundary(string type)
		{
			this.write("-----BEGIN " + type + "-----");
			this.newLine();
		}

		private void writePostEncapsulationBoundary(string type)
		{
			this.write("-----END " + type + "-----");
			this.newLine();
		}
	}

}