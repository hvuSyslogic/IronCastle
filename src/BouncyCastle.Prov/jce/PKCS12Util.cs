using System;

namespace org.bouncycastle.jce
{


	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using Pfx = org.bouncycastle.asn1.pkcs.Pfx;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;

	/// <summary>
	/// Utility class for reencoding PKCS#12 files to definite length.
	/// </summary>
	public class PKCS12Util
	{
		/// <summary>
		/// Just re-encode the outer layer of the PKCS#12 file to definite length encoding.
		/// </summary>
		/// <param name="berPKCS12File"> - original PKCS#12 file </param>
		/// <returns> a byte array representing the DER encoding of the PFX structure </returns>
		/// <exception cref="IOException"> </exception>
		public static byte[] convertToDefiniteLength(byte[] berPKCS12File)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			Pfx pfx = Pfx.getInstance(berPKCS12File);

			bOut.reset();

			dOut.writeObject(pfx);

			return bOut.toByteArray();
		}

		/// <summary>
		/// Re-encode the PKCS#12 structure to definite length encoding at the inner layer
		/// as well, recomputing the MAC accordingly.
		/// </summary>
		/// <param name="berPKCS12File"> - original PKCS12 file. </param>
		/// <param name="provider"> - provider to use for MAC calculation. </param>
		/// <returns> a byte array representing the DER encoding of the PFX structure. </returns>
		/// <exception cref="IOException"> on parsing, encoding errors. </exception>
		public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, string provider)
		{
			Pfx pfx = Pfx.getInstance(berPKCS12File);

			ContentInfo info = pfx.getAuthSafe();

			ASN1OctetString content = ASN1OctetString.getInstance(info.getContent());

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			DEROutputStream dOut = new DEROutputStream(bOut);

			ASN1InputStream contentIn = new ASN1InputStream(content.getOctets());
			ASN1Primitive obj = contentIn.readObject();

			dOut.writeObject(obj);

			info = new ContentInfo(info.getContentType(), new DEROctetString(bOut.toByteArray()));

			MacData mData = pfx.getMacData();
			try
			{
				int itCount = mData.getIterationCount().intValue();
				byte[] data = ASN1OctetString.getInstance(info.getContent()).getOctets();
				byte[] res = calculatePbeMac(mData.getMac().getAlgorithmId().getAlgorithm(), mData.getSalt(), itCount, passwd, data, provider);

				AlgorithmIdentifier algId = new AlgorithmIdentifier(mData.getMac().getAlgorithmId().getAlgorithm(), DERNull.INSTANCE);
				DigestInfo dInfo = new DigestInfo(algId, res);

				mData = new MacData(dInfo, mData.getSalt(), itCount);
			}
			catch (Exception e)
			{
				throw new IOException("error constructing MAC: " + e.ToString());
			}

			pfx = new Pfx(info, mData);

			bOut.reset();

			dOut.writeObject(pfx);

			return bOut.toByteArray();
		}

		private static byte[] calculatePbeMac(ASN1ObjectIdentifier oid, byte[] salt, int itCount, char[] password, byte[] data, string provider)
		{
			SecretKeyFactory keyFact = SecretKeyFactory.getInstance(oid.getId(), provider);
			PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
			PBEKeySpec pbeSpec = new PBEKeySpec(password);
			SecretKey key = keyFact.generateSecret(pbeSpec);

			Mac mac = Mac.getInstance(oid.getId(), provider);
			mac.init(key, defParams);
			mac.update(data);

			return mac.doFinal();
		}
	}

}