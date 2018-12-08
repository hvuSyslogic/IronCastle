using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using McElieceCCA2PrivateKey = org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
	using McElieceCCA2PublicKey = org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceCCA2PrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
	using McElieceCCA2PublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;

	/// <summary>
	/// This class is used to translate between McEliece CCA2 keys and key
	/// specifications.
	/// </summary>
	/// <seealso cref= BCMcElieceCCA2PrivateKey </seealso>
	/// <seealso cref= BCMcElieceCCA2PublicKey </seealso>
	public class McElieceCCA2KeyFactorySpi : KeyFactorySpi, AsymmetricKeyInfoConverter
	{

		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

		/// <summary>
		/// Converts, if possible, a key specification into a
		/// <seealso cref="BCMcElieceCCA2PublicKey"/>. Currently, the following key
		/// specifications are supported:
		/// <seealso cref="X509EncodedKeySpec"/>.
		/// </summary>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the McEliece CCA2 public key </returns>
		/// <exception cref="InvalidKeySpecException"> if the key specification is not supported. </exception>
		public virtual PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is X509EncodedKeySpec)
			{
				// get the DER-encoded Key according to X.509 from the spec
				byte[] encKey = ((X509EncodedKeySpec)keySpec).getEncoded();

				// decode the SubjectPublicKeyInfo data structure to the pki object
				SubjectPublicKeyInfo pki;
				try
				{
					pki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey));
				}
				catch (IOException e)
				{
					throw new InvalidKeySpecException(e.ToString());
				}


				try
				{
					if (PQCObjectIdentifiers_Fields.mcElieceCca2.Equals(pki.getAlgorithm().getAlgorithm()))
					{
						McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(pki.parsePublicKey());

						return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
					}
					else
					{
						throw new InvalidKeySpecException("Unable to recognise OID in McEliece private key");
					}
				}
				catch (IOException cce)
				{
					throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec: " + cce.Message);
				}
			}

			throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.GetType() + ".");
		}

		/// <summary>
		/// Converts, if possible, a key specification into a
		/// <seealso cref="BCMcElieceCCA2PrivateKey"/>. Currently, the following key
		/// specifications are supported:
		/// <seealso cref="PKCS8EncodedKeySpec"/>.
		/// </summary>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the McEliece CCA2 private key </returns>
		/// <exception cref="InvalidKeySpecException"> if the KeySpec is not supported. </exception>
		public virtual PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is PKCS8EncodedKeySpec)
			{
				// get the DER-encoded Key according to PKCS#8 from the spec
				byte[] encKey = ((PKCS8EncodedKeySpec)keySpec).getEncoded();

				// decode the PKCS#8 data structure to the pki object
				PrivateKeyInfo pki;

				try
				{
					pki = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(encKey));
				}
				catch (IOException e)
				{
					throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec: " + e);
				}

				try
				{
					if (PQCObjectIdentifiers_Fields.mcElieceCca2.Equals(pki.getPrivateKeyAlgorithm().getAlgorithm()))
					{
						McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(pki.parsePrivateKey());

						return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
					}
					else
					{
						throw new InvalidKeySpecException("Unable to recognise OID in McEliece public key");
					}
				}
				catch (IOException)
				{
					throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec.");
				}
			}

			throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.GetType() + ".");
		}

		/// <summary>
		/// Converts, if possible, a given key into a key specification. Currently,
		/// the following key specifications are supported:
		/// </summary>
		/// <param name="key">     the key </param>
		/// <param name="keySpec"> the key specification </param>
		/// <returns> the specification of the McEliece CCA2 key </returns>
		/// <exception cref="InvalidKeySpecException"> if the key type or the key specification is not
		/// supported. </exception>
		/// <seealso cref= BCMcElieceCCA2PrivateKey </seealso>
		/// <seealso cref= BCMcElieceCCA2PublicKey </seealso>
		public virtual KeySpec getKeySpec(Key key, Class keySpec)
		{
			if (key is BCMcElieceCCA2PrivateKey)
			{
				if (typeof(PKCS8EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new PKCS8EncodedKeySpec(key.getEncoded());
				}
			}
			else if (key is BCMcElieceCCA2PublicKey)
			{
				if (typeof(X509EncodedKeySpec).isAssignableFrom(keySpec))
				{
					return new X509EncodedKeySpec(key.getEncoded());
				}
			}
			else
			{
				throw new InvalidKeySpecException("Unsupported key type: " + key.GetType() + ".");
			}

			throw new InvalidKeySpecException("Unknown key specification: " + keySpec + ".");
		}

		/// <summary>
		/// Translates a key into a form known by the FlexiProvider. Currently, only
		/// the following "source" keys are supported: <seealso cref="BCMcElieceCCA2PrivateKey"/>,
		/// <seealso cref="BCMcElieceCCA2PublicKey"/>.
		/// </summary>
		/// <param name="key"> the key </param>
		/// <returns> a key of a known key type </returns>
		/// <exception cref="InvalidKeyException"> if the key type is not supported. </exception>
		public virtual Key translateKey(Key key)
		{
			if ((key is BCMcElieceCCA2PrivateKey) || (key is BCMcElieceCCA2PublicKey))
			{
				return key;
			}
			throw new InvalidKeyException("Unsupported key type.");

		}

		public virtual PublicKey generatePublic(SubjectPublicKeyInfo pki)
		{
			// get the inner type inside the BIT STRING
			ASN1Primitive innerType = pki.parsePublicKey();
			McElieceCCA2PublicKey key = McElieceCCA2PublicKey.getInstance(innerType);
			return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeyParameters(key.getN(), key.getT(), key.getG(), Utils.getDigest(key.getDigest()).getAlgorithmName()));
		}

		public virtual PrivateKey generatePrivate(PrivateKeyInfo pki)
		{
			// get the inner type inside the BIT STRING
			ASN1Primitive innerType = pki.parsePrivateKey().toASN1Primitive();
			McElieceCCA2PrivateKey key = McElieceCCA2PrivateKey.getInstance(innerType);
			return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeyParameters(key.getN(), key.getK(), key.getField(), key.getGoppaPoly(), key.getP(), null));
		}

		public virtual KeySpec engineGetKeySpec(Key key, Class tClass)
		{
			// TODO:
			return null; //To change body of implemented methods use File | Settings | File Templates.
		}

		public virtual Key engineTranslateKey(Key key)
		{
			// TODO:
			return null; //To change body of implemented methods use File | Settings | File Templates.
		}
	}

}