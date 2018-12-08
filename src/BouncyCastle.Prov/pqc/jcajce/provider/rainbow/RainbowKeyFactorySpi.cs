using System;

namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using RainbowPrivateKey = org.bouncycastle.pqc.asn1.RainbowPrivateKey;
	using RainbowPublicKey = org.bouncycastle.pqc.asn1.RainbowPublicKey;
	using RainbowPrivateKeySpec = org.bouncycastle.pqc.jcajce.spec.RainbowPrivateKeySpec;
	using RainbowPublicKeySpec = org.bouncycastle.pqc.jcajce.spec.RainbowPublicKeySpec;


	/// <summary>
	/// This class transforms Rainbow keys and Rainbow key specifications.
	/// </summary>
	/// <seealso cref= BCRainbowPublicKey </seealso>
	/// <seealso cref= RainbowPublicKeySpec </seealso>
	/// <seealso cref= BCRainbowPrivateKey </seealso>
	/// <seealso cref= RainbowPrivateKeySpec </seealso>
	public class RainbowKeyFactorySpi : KeyFactorySpi, AsymmetricKeyInfoConverter
	{
		/// <summary>
		/// Converts, if possible, a key specification into a
		/// <seealso cref="BCRainbowPrivateKey"/>. Currently, the following key specifications
		/// are supported: <seealso cref="RainbowPrivateKeySpec"/>, <seealso cref="PKCS8EncodedKeySpec"/>.
		/// <para>
		/// The ASN.1 definition of the key structure is
		/// </para>
		/// <pre>
		///   RainbowPrivateKey ::= SEQUENCE {
		///     oid        OBJECT IDENTIFIER         -- OID identifying the algorithm
		///     A1inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L1
		///     b1         OCTET STRING              -- translation vector of L1
		///     A2inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L2
		///     b2         OCTET STRING              -- translation vector of L2
		///     vi         OCTET STRING              -- num of elmts in each Set S
		///     layers     SEQUENCE OF Layer         -- layers of F
		///   }
		/// 
		///   Layer             ::= SEQUENCE OF Poly
		///   Poly              ::= SEQUENCE {
		///     alpha      SEQUENCE OF OCTET STRING
		///     beta       SEQUENCE OF OCTET STRING
		///     gamma      OCTET STRING
		///     eta        OCTET
		///   }
		/// </pre>
		/// </summary>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the Rainbow private key </returns>
		/// <exception cref="InvalidKeySpecException"> if the KeySpec is not supported. </exception>
		public virtual PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is RainbowPrivateKeySpec)
			{
				return new BCRainbowPrivateKey((RainbowPrivateKeySpec)keySpec);
			}
			else if (keySpec is PKCS8EncodedKeySpec)
			{
				// get the DER-encoded Key according to PKCS#8 from the spec
				byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

				try
				{
					return generatePrivate(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey)));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.GetType() + ".");
		}

		/// <summary>
		/// Converts, if possible, a key specification into a
		/// <seealso cref="BCRainbowPublicKey"/>. Currently, the following key specifications are
		/// supported:<seealso cref="X509EncodedKeySpec"/>.
		/// <para>
		/// The ASN.1 definition of a public key's structure is
		/// </para><pre>
		///    RainbowPublicKey ::= SEQUENCE {
		///      oid            OBJECT IDENTIFIER        -- OID identifying the algorithm
		///      docLength      Integer                  -- length of signable msg
		///      coeffquadratic SEQUENCE OF OCTET STRING -- quadratic (mixed) coefficients
		///      coeffsingular  SEQUENCE OF OCTET STRING -- singular coefficients
		///      coeffscalar       OCTET STRING             -- scalar coefficients
		///       }
		/// </pre>
		/// </summary>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the Rainbow public key </returns>
		/// <exception cref="InvalidKeySpecException"> if the KeySpec is not supported. </exception>
		public virtual PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is RainbowPublicKeySpec)
			{
				return new BCRainbowPublicKey((RainbowPublicKeySpec)keySpec);
			}
			else if (keySpec is X509EncodedKeySpec)
			{
				// get the DER-encoded Key according to X.509 from the spec
				byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

				// decode the SubjectPublicKeyInfo data structure to the pki object
				try
				{
					return generatePublic(SubjectPublicKeyInfo.getInstance(encKey));
				}
				catch (Exception e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}
			}

			throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
		}

		/// <summary>
		/// Converts a given key into a key specification, if possible. Currently the
		/// following specs are supported:
		/// <ul>
		/// <li>for RainbowPublicKey: X509EncodedKeySpec, RainbowPublicKeySpec</li>
		/// <li>for RainbowPrivateKey: PKCS8EncodedKeySpec, RainbowPrivateKeySpec</li>
		/// </ul>
		/// </summary>
		/// <param name="key">     the key </param>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the specification of the CMSS key </returns>
		/// <exception cref="InvalidKeySpecException"> if the key type or key specification is not supported. </exception>
		public KeySpec engineGetKeySpec(Key key, Class keySpec)
		{
			if (key is BCRainbowPrivateKey)
			{
				if (typeof(PKCS8EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new PKCS8EncodedKeySpec(key.getEncoded());
				}
				else if (typeof(RainbowPrivateKeySpec).isAssignableFrom(keySpec))
				{
					BCRainbowPrivateKey privKey = (BCRainbowPrivateKey)key;
					return new RainbowPrivateKeySpec(privKey.getInvA1(), privKey.getB1(), privKey.getInvA2(), privKey.getB2(), privKey.getVi(), privKey.getLayers());
				}
			}
			else if (key is BCRainbowPublicKey)
			{
				if (typeof(X509EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new X509EncodedKeySpec(key.getEncoded());
				}
				else if (typeof(RainbowPublicKeySpec).isAssignableFrom(keySpec))
				{
					BCRainbowPublicKey pubKey = (BCRainbowPublicKey)key;
					return new RainbowPublicKeySpec(pubKey.getDocLength(), pubKey.getCoeffQuadratic(), pubKey.getCoeffSingular(), pubKey.getCoeffScalar());
				}
			}
			else
			{
				throw new InvalidKeySpecException("Unsupported key type: " + key.GetType() + ".");
			}

			throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
		}

		/// <summary>
		/// Translates a key into a form known by the FlexiProvider. Currently the
		/// following key types are supported: RainbowPrivateKey, RainbowPublicKey.
		/// </summary>
		/// <param name="key"> the key </param>
		/// <returns> a key of a known key type </returns>
		/// <exception cref="InvalidKeyException"> if the key is not supported. </exception>
		public Key engineTranslateKey(Key key)
		{
			if (key is BCRainbowPrivateKey || key is BCRainbowPublicKey)
			{
				return key;
			}

			throw new InvalidKeyException("Unsupported key type");
		}

		public virtual PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			RainbowPrivateKey pKey = RainbowPrivateKey.getInstance(keyInfo.parsePrivateKey());

			return new BCRainbowPrivateKey(pKey.getInvA1(), pKey.getB1(), pKey.getInvA2(), pKey.getB2(), pKey.getVi(), pKey.getLayers());
		}

		public virtual PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			RainbowPublicKey pKey = RainbowPublicKey.getInstance(keyInfo.parsePublicKey());

			return new BCRainbowPublicKey(pKey.getDocLength(), pKey.getCoeffQuadratic(), pKey.getCoeffSingular(), pKey.getCoeffScalar());
		}
	}

}