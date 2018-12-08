using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.pkcs
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DLSequence = org.bouncycastle.asn1.DLSequence;
	using AuthenticatedSafe = org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Pfx = org.bouncycastle.asn1.pkcs.Pfx;
	using CMSEncryptedDataGenerator = org.bouncycastle.cms.CMSEncryptedDataGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessableByteArray = org.bouncycastle.cms.CMSProcessableByteArray;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// A builder for the PKCS#12 Pfx key and certificate store.
	/// <para>
	/// For example: you can build a basic key store for the user owning privKey as follows:
	/// </para>
	/// <pre>
	///      X509Certificate[] chain = ....
	///      PublicKey         pubKey = ....
	///      PrivateKey        privKey = ....
	///      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
	/// 
	///      PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[2]);
	/// 
	///      taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Primary Certificate"));
	/// 
	///      PKCS12SafeBagBuilder caCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[1]);
	/// 
	///      caCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Bouncy Intermediate Certificate"));
	/// 
	///      PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(chain[0]);
	/// 
	///      eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
	///      eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));
	/// 
	///      PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(privKey, new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, new CBCBlockCipher(new DESedeEngine())).build(passwd));
	/// 
	///      keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("Eric's Key"));
	///      keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(pubKey));
	/// 
	///      //
	///      // construct the actual key store
	///      //
	///      PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
	/// 
	///      PKCS12SafeBag[] certs = new PKCS12SafeBag[3];
	/// 
	///      certs[0] = eeCertBagBuilder.build();
	///      certs[1] = caCertBagBuilder.build();
	///      certs[2] = taCertBagBuilder.build();
	/// 
	///      pfxPduBuilder.addEncryptedData(new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, new CBCBlockCipher(new RC2Engine())).build(passwd), certs);
	/// 
	///      pfxPduBuilder.addData(keyBagBuilder.build());
	/// 
	///      PKCS12PfxPdu pfx = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwd);
	/// </pre>
	/// 
	/// </summary>
	public class PKCS12PfxPduBuilder
	{
		private ASN1EncodableVector dataVector = new ASN1EncodableVector();

		/// <summary>
		/// Add a SafeBag that is to be included as is.
		/// </summary>
		/// <param name="data"> the SafeBag to add. </param>
		/// <returns> this builder. </returns>
		/// <exception cref="IOException"> </exception>
		public virtual PKCS12PfxPduBuilder addData(PKCS12SafeBag data)
		{
			dataVector.add(new ContentInfo(PKCSObjectIdentifiers_Fields.data, new DEROctetString((new DLSequence(data.toASN1Structure())).getEncoded())));

			return this;
		}

		/// <summary>
		/// Add a SafeBag that is to be wrapped in a EncryptedData object.
		/// </summary>
		/// <param name="dataEncryptor"> the encryptor to use for encoding the data. </param>
		/// <param name="data"> the SafeBag to include. </param>
		/// <returns> this builder. </returns>
		/// <exception cref="IOException"> if a issue occurs processing the data. </exception>
		public virtual PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, PKCS12SafeBag data)
		{
			return addEncryptedData(dataEncryptor, new DERSequence(data.toASN1Structure()));
		}

		/// <summary>
		/// Add a set of SafeBags that are to be wrapped in a EncryptedData object.
		/// </summary>
		/// <param name="dataEncryptor"> the encryptor to use for encoding the data. </param>
		/// <param name="data"> the SafeBags to include. </param>
		/// <returns> this builder. </returns>
		/// <exception cref="IOException"> if a issue occurs processing the data. </exception>
		public virtual PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, PKCS12SafeBag[] data)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != data.Length; i++)
			{
				v.add(data[i].toASN1Structure());
			}

			return addEncryptedData(dataEncryptor, new DLSequence(v));
		}

		private PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, ASN1Sequence data)
		{
			CMSEncryptedDataGenerator envGen = new CMSEncryptedDataGenerator();

			try
			{
				dataVector.add(envGen.generate(new CMSProcessableByteArray(data.getEncoded()), dataEncryptor).toASN1Structure());
			}
			catch (CMSException e)
			{
				throw new PKCSIOException(e.Message, e.InnerException);
			}

			return this;
		}

		/// <summary>
		/// Build the Pfx structure, protecting it with a MAC calculated against the passed in password.
		/// </summary>
		/// <param name="macCalcBuilder"> a builder for a PKCS12 mac calculator. </param>
		/// <param name="password"> the password to use. </param>
		/// <returns> a Pfx object. </returns>
		/// <exception cref="PKCSException"> on a encoding or processing error. </exception>
		public virtual PKCS12PfxPdu build(PKCS12MacCalculatorBuilder macCalcBuilder, char[] password)
		{
			AuthenticatedSafe auth = AuthenticatedSafe.getInstance(new DLSequence(dataVector));
			byte[] encAuth;

			try
			{
				encAuth = auth.getEncoded();
			}
			catch (IOException e)
			{
				throw new PKCSException("unable to encode AuthenticatedSafe: " + e.Message, e);
			}

			ContentInfo mainInfo = new ContentInfo(PKCSObjectIdentifiers_Fields.data, new DEROctetString(encAuth));
			MacData mData = null;

			if (macCalcBuilder != null)
			{
				MacDataGenerator mdGen = new MacDataGenerator(macCalcBuilder);

				mData = mdGen.build(password, encAuth);
			}

			//
			// output the Pfx
			//
			Pfx pfx = new Pfx(mainInfo, mData);

			return new PKCS12PfxPdu(pfx);
		}
	}

}