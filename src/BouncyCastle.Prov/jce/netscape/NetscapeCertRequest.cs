using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce.netscape
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	/// 
	/// 
	/// <summary>
	/// Handles NetScape certificate request (KEYGEN), these are constructed as:
	/// <pre>
	///   SignedPublicKeyAndChallenge ::= SEQUENCE {
	///     publicKeyAndChallenge    PublicKeyAndChallenge,
	///     signatureAlgorithm       AlgorithmIdentifier,
	///     signature                BIT STRING
	///   }
	/// </pre>
	/// 
	/// PublicKey's encoded-format has to be X.509.
	/// 
	/// 
	/// </summary>
	public class NetscapeCertRequest : ASN1Object
	{
		internal AlgorithmIdentifier sigAlg;
		internal AlgorithmIdentifier keyAlg;
		internal byte[] sigBits;
		internal string challenge;
		internal DERBitString content;
		internal PublicKey pubkey;

		private static ASN1Sequence getReq(byte[] r)
		{
			ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(r));

			return ASN1Sequence.getInstance(aIn.readObject());
		}

		public NetscapeCertRequest(byte[] req) : this(getReq(req))
		{
		}

		public NetscapeCertRequest(ASN1Sequence spkac)
		{
			try
			{

				//
				// SignedPublicKeyAndChallenge ::= SEQUENCE {
				//    publicKeyAndChallenge    PublicKeyAndChallenge,
				//    signatureAlgorithm    AlgorithmIdentifier,
				//    signature        BIT STRING
				// }
				//
				if (spkac.size() != 3)
				{
					throw new IllegalArgumentException("invalid SPKAC (size):" + spkac.size());
				}

				sigAlg = AlgorithmIdentifier.getInstance(spkac.getObjectAt(1));
				sigBits = ((DERBitString)spkac.getObjectAt(2)).getOctets();

				//
				// PublicKeyAndChallenge ::= SEQUENCE {
				//    spki            SubjectPublicKeyInfo,
				//    challenge        IA5STRING
				// }
				//
				ASN1Sequence pkac = (ASN1Sequence)spkac.getObjectAt(0);

				if (pkac.size() != 2)
				{
					throw new IllegalArgumentException("invalid PKAC (len): " + pkac.size());
				}

				challenge = ((DERIA5String)pkac.getObjectAt(1)).getString();

				//this could be dangerous, as ASN.1 decoding/encoding
				//could potentially alter the bytes
				content = new DERBitString(pkac);

				SubjectPublicKeyInfo pubkeyinfo = SubjectPublicKeyInfo.getInstance(pkac.getObjectAt(0));

				X509EncodedKeySpec xspec = new X509EncodedKeySpec((new DERBitString(pubkeyinfo)).getBytes());

				keyAlg = pubkeyinfo.getAlgorithm();
				pubkey = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), "BC").generatePublic(xspec);

			}
			catch (Exception e)
			{
				throw new IllegalArgumentException(e.ToString());
			}
		}

		public NetscapeCertRequest(string challenge, AlgorithmIdentifier signing_alg, PublicKey pub_key)
		{

			this.challenge = challenge;
			sigAlg = signing_alg;
			pubkey = pub_key;

			ASN1EncodableVector content_der = new ASN1EncodableVector();
			content_der.add(getKeySpec());
			//content_der.add(new SubjectPublicKeyInfo(sigAlg, new RSAPublicKeyStructure(pubkey.getModulus(), pubkey.getPublicExponent()).getDERObject()));
			content_der.add(new DERIA5String(challenge));

			try
			{
				content = new DERBitString(new DERSequence(content_der));
			}
			catch (IOException e)
			{
				throw new InvalidKeySpecException("exception encoding key: " + e.ToString());
			}
		}

		public virtual string getChallenge()
		{
			return challenge;
		}

		public virtual void setChallenge(string value)
		{
			challenge = value;
		}

		public virtual AlgorithmIdentifier getSigningAlgorithm()
		{
			return sigAlg;
		}

		public virtual void setSigningAlgorithm(AlgorithmIdentifier value)
		{
			sigAlg = value;
		}

		public virtual AlgorithmIdentifier getKeyAlgorithm()
		{
			return keyAlg;
		}

		public virtual void setKeyAlgorithm(AlgorithmIdentifier value)
		{
			keyAlg = value;
		}

		public virtual PublicKey getPublicKey()
		{
			return pubkey;
		}

		public virtual void setPublicKey(PublicKey value)
		{
			pubkey = value;
		}

		public virtual bool verify(string challenge)
		{
			if (!challenge.Equals(this.challenge))
			{
				return false;
			}

			//
			// Verify the signature .. shows the response was generated
			// by someone who knew the associated private key
			//
			Signature sig = Signature.getInstance(sigAlg.getAlgorithm().getId(), "BC");
			sig.initVerify(pubkey);
			sig.update(content.getBytes());

			return sig.verify(sigBits);
		}

		public virtual void sign(PrivateKey priv_key)
		{
			sign(priv_key, null);
		}

		public virtual void sign(PrivateKey priv_key, SecureRandom rand)
		{
			Signature sig = Signature.getInstance(sigAlg.getAlgorithm().getId(), "BC");

			if (rand != null)
			{
				sig.initSign(priv_key, rand);
			}
			else
			{
				sig.initSign(priv_key);
			}

			ASN1EncodableVector pkac = new ASN1EncodableVector();

			pkac.add(getKeySpec());
			pkac.add(new DERIA5String(challenge));

			try
			{
				sig.update((new DERSequence(pkac)).getEncoded(ASN1Encoding_Fields.DER));
			}
			catch (IOException ioe)
			{
				throw new SignatureException(ioe.Message);
			}

			sigBits = sig.sign();
		}

		private ASN1Primitive getKeySpec()
		{
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			ASN1Primitive obj = null;
			try
			{

				baos.write(pubkey.getEncoded());
				baos.close();

				ASN1InputStream derin = new ASN1InputStream(new ByteArrayInputStream(baos.toByteArray()));

				obj = derin.readObject();
			}
			catch (IOException ioe)
			{
				throw new InvalidKeySpecException(ioe.Message);
			}
			return obj;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector spkac = new ASN1EncodableVector();
			ASN1EncodableVector pkac = new ASN1EncodableVector();

			try
			{
				pkac.add(getKeySpec());
			}
			catch (Exception)
			{
				//ignore
			}

			pkac.add(new DERIA5String(challenge));

			spkac.add(new DERSequence(pkac));
			spkac.add(sigAlg);
			spkac.add(new DERBitString(sigBits));

			return new DERSequence(spkac);
		}
	}

}