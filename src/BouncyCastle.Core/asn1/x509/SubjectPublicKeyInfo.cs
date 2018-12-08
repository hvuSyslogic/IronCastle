using System.IO;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// The object that contains the public key stored in a certificate.
	/// <para>
	/// The getEncoded() method in the public keys in the JCE produces a DER
	/// encoded one of these.
	/// </para>
	/// </summary>
	public class SubjectPublicKeyInfo : ASN1Object
	{
		private AlgorithmIdentifier algId;
		private DERBitString keyData;

		public static SubjectPublicKeyInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static SubjectPublicKeyInfo getInstance(object obj)
		{
			if (obj is SubjectPublicKeyInfo)
			{
				return (SubjectPublicKeyInfo)obj;
			}
			else if (obj != null)
			{
				return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public SubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable publicKey)
		{
			this.keyData = new DERBitString(publicKey);
			this.algId = algId;
		}

		public SubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] publicKey)
		{
			this.keyData = new DERBitString(publicKey);
			this.algId = algId;
		}

		/// @deprecated use SubjectPublicKeyInfo.getInstance() 
		public SubjectPublicKeyInfo(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			this.algId = AlgorithmIdentifier.getInstance(e.nextElement());
			this.keyData = DERBitString.getInstance(e.nextElement());
		}

		public virtual AlgorithmIdentifier getAlgorithm()
		{
			return algId;
		}

		/// @deprecated use getAlgorithm() 
		/// <returns>    alg ID. </returns>
		public virtual AlgorithmIdentifier getAlgorithmId()
		{
			return algId;
		}

		/// <summary>
		/// for when the public key is an encoded object - if the bitstring
		/// can't be decoded this routine throws an IOException.
		/// </summary>
		/// <exception cref="IOException"> - if the bit string doesn't represent a DER
		/// encoded object. </exception>
		/// <returns> the public key as an ASN.1 primitive. </returns>
		public virtual ASN1Primitive parsePublicKey()
		{
			return ASN1Primitive.fromByteArray(keyData.getOctets());
		}

		/// <summary>
		/// for when the public key is an encoded object - if the bitstring
		/// can't be decoded this routine throws an IOException.
		/// </summary>
		/// <exception cref="IOException"> - if the bit string doesn't represent a DER
		/// encoded object. </exception>
		/// @deprecated use parsePublicKey 
		/// <returns> the public key as an ASN.1 primitive. </returns>
		public virtual ASN1Primitive getPublicKey()
		{
			return ASN1Primitive.fromByteArray(keyData.getOctets());
		}

		/// <summary>
		/// for when the public key is raw bits.
		/// </summary>
		/// <returns> the public key as the raw bit string... </returns>
		public virtual DERBitString getPublicKeyData()
		{
			return keyData;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// SubjectPublicKeyInfo ::= SEQUENCE {
		///                          algorithm AlgorithmIdentifier,
		///                          publicKey BIT STRING }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(algId);
			v.add(keyData);

			return new DERSequence(v);
		}
	}

}