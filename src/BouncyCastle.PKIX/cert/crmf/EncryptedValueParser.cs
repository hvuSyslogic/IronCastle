namespace org.bouncycastle.cert.crmf
{

	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Parser for EncryptedValue structures.
	/// </summary>
	public class EncryptedValueParser
	{
		private EncryptedValue value;
		private EncryptedValuePadder padder;

		/// <summary>
		/// Basic constructor - create a parser to read the passed in value.
		/// </summary>
		/// <param name="value"> the value to be parsed. </param>
		public EncryptedValueParser(EncryptedValue value)
		{
			this.value = value;
		}

		/// <summary>
		/// Create a parser to read the passed in value, assuming the padder was
		/// applied to the data prior to encryption.
		/// </summary>
		/// <param name="value">  the value to be parsed. </param>
		/// <param name="padder"> the padder to be used to remove padding from the decrypted value.. </param>
		public EncryptedValueParser(EncryptedValue value, EncryptedValuePadder padder)
		{
			this.value = value;
			this.padder = padder;
		}

		public virtual AlgorithmIdentifier getIntendedAlg()
		{
			return value.getIntendedAlg();
		}

		private byte[] decryptValue(ValueDecryptorGenerator decGen)
		{
			if (value.getValueHint() != null)
			{
				throw new UnsupportedOperationException();
			}

			InputDecryptor decryptor = decGen.getValueDecryptor(value.getKeyAlg(), value.getSymmAlg(), value.getEncSymmKey().getBytes());
			InputStream dataIn = decryptor.getInputStream(new ByteArrayInputStream(value.getEncValue().getBytes()));
			try
			{
				byte[] data = Streams.readAll(dataIn);

				if (padder != null)
				{
					return padder.getUnpaddedData(data);
				}

				return data;
			}
			catch (IOException e)
			{
				throw new CRMFException("Cannot parse decrypted data: " + e.Message, e);
			}
		}

		/// <summary>
		/// Read a X.509 certificate.
		/// </summary>
		/// <param name="decGen"> the decryptor generator to decrypt the encrypted value. </param>
		/// <returns> an X509CertificateHolder containing the certificate read. </returns>
		/// <exception cref="CRMFException"> if the decrypted data cannot be parsed, or a decryptor cannot be generated. </exception>
		public virtual X509CertificateHolder readCertificateHolder(ValueDecryptorGenerator decGen)
		{
			return new X509CertificateHolder(Certificate.getInstance(decryptValue(decGen)));
		}

		/// <summary>
		/// Read a PKCS#8 PrivateKeyInfo.
		/// </summary>
		/// <param name="decGen"> the decryptor generator to decrypt the encrypted value. </param>
		/// <returns> an PrivateKeyInfo containing the private key that was read. </returns>
		/// <exception cref="CRMFException"> if the decrypted data cannot be parsed, or a decryptor cannot be generated. </exception>
		public virtual PrivateKeyInfo readPrivateKeyInfo(ValueDecryptorGenerator decGen)
		{
			return PrivateKeyInfo.getInstance(decryptValue(decGen));
		}

		/// <summary>
		/// Read a pass phrase.
		/// </summary>
		/// <param name="decGen"> the decryptor generator to decrypt the encrypted value. </param>
		/// <returns> a pass phrase as recovered from the encrypted value. </returns>
		/// <exception cref="CRMFException"> if the decrypted data cannot be parsed, or a decryptor cannot be generated. </exception>
		public virtual char[] readPassphrase(ValueDecryptorGenerator decGen)
		{
			return Strings.fromUTF8ByteArray(decryptValue(decGen)).ToCharArray();
		}
	}

}