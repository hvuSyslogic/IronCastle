using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.cert.bc
{

	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using SubjectPublicKeyInfoFactory = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class BcX509ExtensionUtils : X509ExtensionUtils
	{
		/// <summary>
		/// Create a utility class pre-configured with a SHA-1 digest calculator based on the
		/// BC implementation.
		/// </summary>
		public BcX509ExtensionUtils() : base(new SHA1DigestCalculator())
		{
		}

		public BcX509ExtensionUtils(DigestCalculator calculator) : base(calculator)
		{
		}

		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(AsymmetricKeyParameter publicKey)
		{
			return base.createAuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
		}

		/// <summary>
		/// Return a RFC 3280 type 1 key identifier. As in:
		/// <pre>
		/// (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		/// value of the BIT STRING subjectPublicKey (excluding the tag,
		/// length, and number of unused bits).
		/// </pre> </summary>
		/// <param name="publicKey"> the key object containing the key identifier is to be based on. </param>
		/// <returns> the key identifier. </returns>
		public virtual SubjectKeyIdentifier createSubjectKeyIdentifier(AsymmetricKeyParameter publicKey)
		{
			return base.createSubjectKeyIdentifier(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
		}

		public class SHA1DigestCalculator : DigestCalculator
		{
			internal ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
			}

			public virtual OutputStream getOutputStream()
			{
				return bOut;
			}

			public virtual byte[] getDigest()
			{
				byte[] bytes = bOut.toByteArray();

				bOut.reset();

				Digest sha1 = new SHA1Digest();

				sha1.update(bytes, 0, bytes.Length);

				byte[] digest = new byte[sha1.getDigestSize()];

				sha1.doFinal(digest, 0);

				return digest;
			}
		}
	}

}