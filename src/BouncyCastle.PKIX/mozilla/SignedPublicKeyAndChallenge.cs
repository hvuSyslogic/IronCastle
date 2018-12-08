using org.bouncycastle.asn1.mozilla;

using System;

namespace org.bouncycastle.mozilla
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using PublicKeyAndChallenge = org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// This is designed to parse the SignedPublicKeyAndChallenge created by the
	/// KEYGEN tag included by Mozilla based browsers.
	///  <pre>
	///  PublicKeyAndChallenge ::= SEQUENCE {
	///    spki SubjectPublicKeyInfo,
	///    challenge IA5STRING
	///  }
	/// 
	///  SignedPublicKeyAndChallenge ::= SEQUENCE {
	///    publicKeyAndChallenge PublicKeyAndChallenge,
	///    signatureAlgorithm AlgorithmIdentifier,
	///    signature BIT STRING
	///  }
	///  </pre>
	/// </summary>
	public class SignedPublicKeyAndChallenge : Encodable
	{
		protected internal readonly SignedPublicKeyAndChallenge spkacSeq;

		public SignedPublicKeyAndChallenge(byte[] bytes)
		{
			spkacSeq = SignedPublicKeyAndChallenge.getInstance(bytes);
		}

		public SignedPublicKeyAndChallenge(SignedPublicKeyAndChallenge @struct)
		{
			this.spkacSeq = @struct;
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for this challenge.
		/// </summary>
		/// <returns> a SignedPublicKeyAndChallenge object. </returns>
		public virtual SignedPublicKeyAndChallenge toASN1Structure()
		{
			 return spkacSeq;
		}

		/// @deprecated use toASN1Structure 
		public virtual ASN1Primitive toASN1Primitive()
		{
			return spkacSeq.toASN1Primitive();
		}

		public virtual PublicKeyAndChallenge getPublicKeyAndChallenge()
		{
			return spkacSeq.getPublicKeyAndChallenge();
		}

		public virtual bool isSignatureValid(ContentVerifierProvider verifierProvider)
		{
			ContentVerifier verifier = verifierProvider.get(spkacSeq.getSignatureAlgorithm());

			OutputStream sOut = verifier.getOutputStream();
			DEROutputStream dOut = new DEROutputStream(sOut);

			dOut.writeObject(spkacSeq.getPublicKeyAndChallenge());

			sOut.close();

			return verifier.verify(spkacSeq.getSignature().getOctets());
		}

		/// @deprecated use ContentVerifierProvider method 
		public virtual bool verify()
		{
			return verify((string)null);
		}

		/// @deprecated use ContentVerifierProvider method 
		public virtual bool verify(string provider)
		{
			Signature sig = null;
			if (string.ReferenceEquals(provider, null))
			{
				sig = Signature.getInstance(spkacSeq.getSignatureAlgorithm().getAlgorithm().getId());
			}
			else
			{
				sig = Signature.getInstance(spkacSeq.getSignatureAlgorithm().getAlgorithm().getId(), provider);
			}
			PublicKey pubKey = this.getPublicKey(provider);
			sig.initVerify(pubKey);
			try
			{
				sig.update(spkacSeq.getPublicKeyAndChallenge().getEncoded());

				return sig.verify(spkacSeq.getSignature().getBytes());
			}
			catch (Exception)
			{
				throw new InvalidKeyException("error encoding public key");
			}
		}

		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
		}

		public virtual string getChallenge()
		{
			return spkacSeq.getPublicKeyAndChallenge().getChallenge().getString();
		}

		/// @deprecated use JcaSignedPublicKeyAndChallenge.getPublicKey() 
		public virtual PublicKey getPublicKey(string provider)
		{
			SubjectPublicKeyInfo subjectPKInfo = spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
			try
			{
				DERBitString bStr = new DERBitString(subjectPKInfo);
				X509EncodedKeySpec xspec = new X509EncodedKeySpec(bStr.getOctets());


				AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();

				KeyFactory factory = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(),provider);

				return factory.generatePublic(xspec);

			}
			catch (Exception)
			{
				throw new InvalidKeyException("error encoding public key");
			}
		}

		public virtual byte[] getEncoded()
		{
			return toASN1Structure().getEncoded();
		}
	}

}