using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.jcajce.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

	/// <summary>
	/// General JCA/JCE utility methods.
	/// </summary>
	public class JcaJceUtils
	{
		private JcaJceUtils()
		{

		}

		/// <summary>
		/// Extract an ASN.1 encodable from an AlgorithmParameters object.
		/// </summary>
		/// <param name="params"> the object to get the encoding used to create the return value. </param>
		/// <returns> an ASN.1 object representing the primitives making up the params parameter. </returns>
		/// <exception cref="IOException"> if an encoding cannot be extracted. </exception>
		/// @deprecated use AlgorithmParametersUtils.extractParameters(AlgorithmParameters params) 
		public static ASN1Encodable extractParameters(AlgorithmParameters @params)
		{
			// we try ASN.1 explicitly first just in case and then role back to the default.
			ASN1Encodable asn1Params;
			try
			{
				asn1Params = ASN1Primitive.fromByteArray(@params.getEncoded("ASN.1"));
			}
			catch (Exception)
			{
				asn1Params = ASN1Primitive.fromByteArray(@params.getEncoded());
			}

			return asn1Params;
		}

		/// <summary>
		/// Load an AlgorithmParameters object with the passed in ASN.1 encodable - if possible.
		/// </summary>
		/// <param name="params"> the AlgorithmParameters object to be initialised. </param>
		/// <param name="sParams"> the ASN.1 encodable to initialise params with. </param>
		/// <exception cref="IOException"> if the parameters cannot be initialised. </exception>
		/// @deprecated use AlgorithmParametersUtils.loadParameters(AlgorithmParameters params, ASN1Encodable sParams) 
		public static void loadParameters(AlgorithmParameters @params, ASN1Encodable sParams)
		{
			// we try ASN.1 explicitly first just in case and then role back to the default.
			try
			{
				@params.init(sParams.toASN1Primitive().getEncoded(), "ASN.1");
			}
			catch (Exception)
			{
				@params.init(sParams.toASN1Primitive().getEncoded());
			}
		}

		/// <summary>
		/// Attempt to find a standard JCA name for the digest represented by the past in OID.
		/// </summary>
		/// <param name="digestAlgOID"> the OID of the digest algorithm of interest. </param>
		/// <returns> a string representing the standard name - the OID as a string if none available. </returns>
		/// @deprecated use MessageDigestUtils,getDigestName() 
		public static string getDigestAlgName(ASN1ObjectIdentifier digestAlgOID)
		{
			if (PKCSObjectIdentifiers_Fields.md5.Equals(digestAlgOID))
			{
				return "MD5";
			}
			else if (OIWObjectIdentifiers_Fields.idSHA1.Equals(digestAlgOID))
			{
				return "SHA1";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha224.Equals(digestAlgOID))
			{
				return "SHA224";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha256.Equals(digestAlgOID))
			{
				return "SHA256";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha384.Equals(digestAlgOID))
			{
				return "SHA384";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha512.Equals(digestAlgOID))
			{
				return "SHA512";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd128.Equals(digestAlgOID))
			{
				return "RIPEMD128";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd160.Equals(digestAlgOID))
			{
				return "RIPEMD160";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd256.Equals(digestAlgOID))
			{
				return "RIPEMD256";
			}
			else if (CryptoProObjectIdentifiers_Fields.gostR3411.Equals(digestAlgOID))
			{
				return "GOST3411";
			}
			else
			{
				return digestAlgOID.getId();
			}
		}
	}

}