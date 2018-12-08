using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.isismtt.ocsp
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ISIS-MTT PROFILE: The responder may include this extension in a response to
	/// send the hash of the requested certificate to the responder. This hash is
	/// cryptographically bound to the certificate and serves as evidence that the
	/// certificate is known to the responder (i.e. it has been issued and is present
	/// in the directory). Hence, this extension is a means to provide a positive
	/// statement of availability as described in T8.[8]. As explained in T13.[1],
	/// clients may rely on this information to be able to validate signatures after
	/// the expiry of the corresponding certificate. Hence, clients MUST support this
	/// extension. If a positive statement of availability is to be delivered, this
	/// extension syntax and OID MUST be used.
	/// <pre>
	///     CertHash ::= SEQUENCE {
	///       hashAlgorithm AlgorithmIdentifier,
	///       certificateHash OCTET STRING
	///     }
	/// </pre>
	/// </summary>
	public class CertHash : ASN1Object
	{

		private AlgorithmIdentifier hashAlgorithm;
		private byte[] certificateHash;

		public static CertHash getInstance(object obj)
		{
			if (obj == null || obj is CertHash)
			{
				return (CertHash)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new CertHash((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type CertHash:
		/// <pre>
		///     CertHash ::= SEQUENCE {
		///       hashAlgorithm AlgorithmIdentifier,
		///       certificateHash OCTET STRING
		///     }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private CertHash(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			certificateHash = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="hashAlgorithm">   The hash algorithm identifier. </param>
		/// <param name="certificateHash"> The hash of the whole DER encoding of the certificate. </param>
		public CertHash(AlgorithmIdentifier hashAlgorithm, byte[] certificateHash)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.certificateHash = new byte[certificateHash.Length];
			JavaSystem.arraycopy(certificateHash, 0, this.certificateHash, 0, certificateHash.Length);
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual byte[] getCertificateHash()
		{
			return Arrays.clone(certificateHash);
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///     CertHash ::= SEQUENCE {
		///       hashAlgorithm AlgorithmIdentifier,
		///       certificateHash OCTET STRING
		///     }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			vec.add(hashAlgorithm);
			vec.add(new DEROctetString(certificateHash));
			return new DERSequence(vec);
		}
	}

}