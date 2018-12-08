using org.bouncycastle.asn1.pkcs;

using System;

namespace javax.crypto
{


	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERObjectIdentifier = org.bouncycastle.asn1.DERObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// This class implements the <code>EncryptedPrivateKeyInfo</code> type
	///  as defined in PKCS #8.
	/// <para>Its ASN.1 definition is as follows:
	/// 
	/// <pre>
	/// EncryptedPrivateKeyInfo ::=  SEQUENCE {
	///     encryptionAlgorithm   AlgorithmIdentifier,
	///     encryptedData   OCTET STRING }
	/// 
	/// AlgorithmIdentifier  ::=  SEQUENCE  {
	///     algorithm              OBJECT IDENTIFIER,
	///     parameters             ANY DEFINED BY algorithm OPTIONAL  }
	/// </pre>
	/// </para>
	/// </summary>
	public class EncryptedPrivateKeyInfo
	{
		private EncryptedPrivateKeyInfo infoObj;
		private AlgorithmParameters algP;

		/*
		 * Constructs (i.e., parses) an <code>EncryptedPrivateKeyInfo</code> from
		 * its ASN.1 encoding.
		 *
		 * @param encoded the ASN.1 encoding of this object.
		 * @exception NullPointerException if the <code>encoded</code> is null.
		 * @exception IOException if error occurs when parsing the ASN.1 encoding.
		 */
		public EncryptedPrivateKeyInfo(byte[] encoded)
		{
			if (encoded == null)
			{
				throw new NullPointerException("parameters null");
			}

			ByteArrayInputStream bIn = new ByteArrayInputStream(encoded);
			ASN1InputStream dIn = new ASN1InputStream(bIn);

			infoObj = EncryptedPrivateKeyInfo.getInstance((ASN1Sequence)dIn.readObject());

			try
			{
				algP = this.getParameters();
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new IOException("can't create parameters: " + e.ToString());
			}
		}

		/*
		 * Constructs an <code>EncryptedPrivateKeyInfo</code> from the
		 * encryption algorithm name and the encrypted data.
		 * <p>Note: the <code>encrypedData</code> is cloned when constructing
		 * this object.
		 * <p>
		 * If encryption algorithm has associated parameters use the constructor
		 * with AlgorithmParameters as the parameter.
		 *
		 * @param algName algorithm name.
		 * @param encryptedData encrypted data.
		 * @exception NullPointerException if <code>algName</code> or <code>encryptedData</code> is null.
		 * @exception IllegalArgumentException if <code>encryptedData</code> is empty, i.e. 0-length.
		 * @exception NoSuchAlgorithmException if the specified algName is not supported.
		 */
		public EncryptedPrivateKeyInfo(string algName, byte[] encryptedData)
		{
			if (string.ReferenceEquals(algName, null) || encryptedData == null)
			{
				throw new NullPointerException("parameters null");
			}

			AlgorithmIdentifier kAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(algName), null);

			infoObj = new EncryptedPrivateKeyInfo(kAlgId, (byte[])encryptedData.Clone());
			algP = this.getParameters();
		}

		/// <summary>
		/// Constructs an <code>EncryptedPrivateKeyInfo</code> from the
		/// encryption algorithm parameters and the encrypted data.
		/// <para>Note: the <code>encrypedData</code> is cloned when constructing
		/// this object.
		/// 
		/// </para>
		/// </summary>
		/// <param name="algParams"> the algorithm parameters for the encryption 
		/// algorithm. <code>algParams.getEncoded()</code> should return
		/// the ASN.1 encoded bytes of the <code>parameters</code> field
		/// of the <code>AlgorithmIdentifer</code> component of the
		/// <code>EncryptedPrivateKeyInfo</code> type. </param>
		/// <param name="encryptedData"> encrypted data. </param>
		/// <exception cref="NullPointerException"> if <code>algParams</code> or <code>encryptedData</code> is null. </exception>
		/// <exception cref="IllegalArgumentException"> if <code>encryptedData</code> is empty, i.e. 0-length. </exception>
		/// <exception cref="NoSuchAlgorithmException"> if the specified algName of the specified <code>algParams</code> parameter is not supported. </exception>
		public EncryptedPrivateKeyInfo(AlgorithmParameters algParams, byte[] encryptedData)
		{
			if (algParams == null || encryptedData == null)
			{
				throw new NullPointerException("parameters null");
			}

			AlgorithmIdentifier kAlgId = null;

			try
			{
				ByteArrayInputStream bIn = new ByteArrayInputStream(algParams.getEncoded());
				ASN1InputStream dIn = new ASN1InputStream(bIn);

				kAlgId = new AlgorithmIdentifier(new DERObjectIdentifier(algParams.getAlgorithm()), dIn.readObject());
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("error in encoding: " + e.ToString());
			}

			infoObj = new EncryptedPrivateKeyInfo(kAlgId, (byte[])encryptedData.Clone());
			algP = this.getParameters();
		}

		/// <summary>
		/// Returns the encryption algorithm.
		/// 
		/// @returns the algorithm name.
		/// </summary>
		public virtual string getAlgName()
		{
			return infoObj.getEncryptionAlgorithm().getAlgorithm().getId();
		}

		private AlgorithmParameters getParameters()
		{
			AlgorithmParameters ap = AlgorithmParameters.getInstance(this.getAlgName());
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			try
			{
				dOut.writeObject(infoObj.getEncryptionAlgorithm().getParameters());
				dOut.close();

				ap.init(bOut.toByteArray());
			}
			catch (IOException)
			{
				throw new NoSuchAlgorithmException("unable to parse parameters");
			}

			return ap;
		}

		/// <summary>
		/// Returns the algorithm parameters used by the encryption algorithm.
		/// 
		/// @returns the algorithm parameters.
		/// </summary>
		public virtual AlgorithmParameters getAlgParameters()
		{
			return algP;
		}

		/// <summary>
		/// Returns a copy of the encrypted data.
		/// 
		/// @returns a copy of the encrypted data.
		/// </summary>
		public virtual byte[] getEncryptedData()
		{
			return infoObj.getEncryptedData();
		}

		/// <summary>
		/// Extract the enclosed PKCS8EncodedKeySpec object from the 
		/// encrypted data and return it.
		/// </summary>
		/// <returns> the PKCS8EncodedKeySpec object. </returns>
		/// <exception cref="InvalidKeySpecException"> if the given cipher is 
		/// inappropriate for the encrypted data or the encrypted
		/// data is corrupted and cannot be decrypted. </exception>
		public virtual PKCS8EncodedKeySpec getKeySpec(Cipher c)
		{
			try
			{
				return new PKCS8EncodedKeySpec(c.doFinal(this.getEncryptedData()));
			}
			catch (Exception e)
			{
				throw new InvalidKeySpecException("can't get keySpec: " + e.ToString());
			}
		}

		/// <summary>
		/// Returns the ASN.1 encoding of this object.
		/// 
		/// @returns the ASN.1 encoding. </summary>
		/// <exception cref="IOException"> if error occurs when constructing its ASN.1 encoding. </exception>
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			dOut.writeObject(infoObj);
			dOut.close();

			return bOut.toByteArray();
		}
	}

}