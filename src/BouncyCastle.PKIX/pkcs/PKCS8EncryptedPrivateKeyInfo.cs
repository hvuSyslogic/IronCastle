using System;

namespace org.bouncycastle.pkcs
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InputDecryptor = org.bouncycastle.@operator.InputDecryptor;
	using InputDecryptorProvider = org.bouncycastle.@operator.InputDecryptorProvider;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Holding class for a PKCS#8 EncryptedPrivateKeyInfo structure.
	/// </summary>
	public class PKCS8EncryptedPrivateKeyInfo
	{
		private EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

		private static EncryptedPrivateKeyInfo parseBytes(byte[] pkcs8Encoding)
		{
			try
			{
				return EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pkcs8Encoding));
			}
			catch (ClassCastException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new PKCSIOException("malformed data: " + e.getMessage(), e);
			}
		}

		public PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
		{
			this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
		}

		public PKCS8EncryptedPrivateKeyInfo(byte[] encryptedPrivateKeyInfo) : this(parseBytes(encryptedPrivateKeyInfo))
		{
		}

		public virtual AlgorithmIdentifier getEncryptionAlgorithm()
		{
			return encryptedPrivateKeyInfo.getEncryptionAlgorithm();
		}

		public virtual byte[] getEncryptedData()
		{
			return encryptedPrivateKeyInfo.getEncryptedData();
		}

		public virtual EncryptedPrivateKeyInfo toASN1Structure()
		{
			 return encryptedPrivateKeyInfo;
		}

		public virtual byte[] getEncoded()
		{
			return encryptedPrivateKeyInfo.getEncoded();
		}

		public virtual PrivateKeyInfo decryptPrivateKeyInfo(InputDecryptorProvider inputDecryptorProvider)
		{
			try
			{
				InputDecryptor decrytor = inputDecryptorProvider.get(encryptedPrivateKeyInfo.getEncryptionAlgorithm());

				ByteArrayInputStream encIn = new ByteArrayInputStream(encryptedPrivateKeyInfo.getEncryptedData());

				return PrivateKeyInfo.getInstance(Streams.readAll(decrytor.getInputStream(encIn)));
			}
			catch (Exception e)
			{
				throw new PKCSException("unable to read encrypted data: " + e.Message, e);
			}
		}
	}

}