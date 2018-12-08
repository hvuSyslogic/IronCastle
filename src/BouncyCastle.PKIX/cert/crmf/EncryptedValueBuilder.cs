namespace org.bouncycastle.cert.crmf
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using KeyWrapper = org.bouncycastle.@operator.KeyWrapper;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using PKCS8EncryptedPrivateKeyInfoBuilder = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Builder for EncryptedValue structures.
	/// </summary>
	public class EncryptedValueBuilder
	{
		private KeyWrapper wrapper;
		private OutputEncryptor encryptor;
		private EncryptedValuePadder padder;

		/// <summary>
		/// Create a builder that makes EncryptedValue structures.
		/// </summary>
		/// <param name="wrapper"> a wrapper for key used to encrypt the actual data contained in the EncryptedValue. </param>
		/// <param name="encryptor">  an output encryptor to encrypt the actual data contained in the EncryptedValue.  </param>
		public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor) : this(wrapper, encryptor, null)
		{
		}

		/// <summary>
		/// Create a builder that makes EncryptedValue structures with fixed length blocks padded using the passed in padder.
		/// </summary>
		/// <param name="wrapper"> a wrapper for key used to encrypt the actual data contained in the EncryptedValue. </param>
		/// <param name="encryptor">  an output encryptor to encrypt the actual data contained in the EncryptedValue. </param>
		/// <param name="padder"> a padder to ensure that the EncryptedValue created will always be a constant length. </param>
		public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor, EncryptedValuePadder padder)
		{
			this.wrapper = wrapper;
			this.encryptor = encryptor;
			this.padder = padder;
		}

		/// <summary>
		/// Build an EncryptedValue structure containing the passed in pass phrase.
		/// </summary>
		/// <param name="revocationPassphrase">  a revocation pass phrase. </param>
		/// <returns> an EncryptedValue containing the encrypted pass phrase. </returns>
		/// <exception cref="CRMFException"> on a failure to encrypt the data, or wrap the symmetric key for this value. </exception>
		public virtual EncryptedValue build(char[] revocationPassphrase)
		{
			return encryptData(padData(Strings.toUTF8ByteArray(revocationPassphrase)));
		}

		/// <summary>
		/// Build an EncryptedValue structure containing the certificate contained in
		/// the passed in holder.
		/// </summary>
		/// <param name="holder">  a holder containing a certificate. </param>
		/// <returns> an EncryptedValue containing the encrypted certificate. </returns>
		/// <exception cref="CRMFException"> on a failure to encrypt the data, or wrap the symmetric key for this value. </exception>
		public virtual EncryptedValue build(X509CertificateHolder holder)
		{
			try
			{
				return encryptData(padData(holder.getEncoded()));
			}
			catch (IOException e)
			{
				throw new CRMFException("cannot encode certificate: " + e.Message, e);
			}
		}

		/// <summary>
		/// Build an EncryptedValue structure containing the private key contained in
		/// the passed info structure.
		/// </summary>
		/// <param name="privateKeyInfo">  a PKCS#8 private key info structure. </param>
		/// <returns> an EncryptedValue containing an EncryptedPrivateKeyInfo structure. </returns>
		/// <exception cref="CRMFException"> on a failure to encrypt the data, or wrap the symmetric key for this value. </exception>
		public virtual EncryptedValue build(PrivateKeyInfo privateKeyInfo)
		{
			PKCS8EncryptedPrivateKeyInfoBuilder encInfoBldr = new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo);

			AlgorithmIdentifier intendedAlg = privateKeyInfo.getPrivateKeyAlgorithm();
			AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
			DERBitString encSymmKey;

			try
			{
				PKCS8EncryptedPrivateKeyInfo encInfo = encInfoBldr.build(encryptor);

				encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getKey()));

				AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();
				ASN1OctetString valueHint = null;

				return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, new DERBitString(encInfo.getEncryptedData()));
			}
			catch (IllegalStateException e)
			{
				throw new CRMFException("cannot encode key: " + e.getMessage(), e);
			}
			catch (OperatorException e)
			{
				throw new CRMFException("cannot wrap key: " + e.getMessage(), e);
			}
		}

		private EncryptedValue encryptData(byte[] data)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			OutputStream eOut = encryptor.getOutputStream(bOut);

			try
			{
				eOut.write(data);

				eOut.close();
			}
			catch (IOException e)
			{
				throw new CRMFException("cannot process data: " + e.Message, e);
			}

			AlgorithmIdentifier intendedAlg = null;
			AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
			DERBitString encSymmKey;

			try
			{
				wrapper.generateWrappedKey(encryptor.getKey());
				encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getKey()));
			}
			catch (OperatorException e)
			{
				throw new CRMFException("cannot wrap key: " + e.Message, e);
			}

			AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();
			ASN1OctetString valueHint = null;
			DERBitString encValue = new DERBitString(bOut.toByteArray());

			return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
		}

		private byte[] padData(byte[] data)
		{
			if (padder != null)
			{
				return padder.getPaddedData(data);
			}

			return data;
		}
	}

}