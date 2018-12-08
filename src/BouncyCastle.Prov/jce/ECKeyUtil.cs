using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	/// <summary>
	/// Utility class to allow conversion of EC key parameters to explicit from named
	/// curves and back (where possible).
	/// </summary>
	public class ECKeyUtil
	{
		/// <summary>
		/// Convert a passed in public EC key to have explicit parameters. If the key
		/// is already using explicit parameters it is returned.
		/// </summary>
		/// <param name="key"> key to be converted </param>
		/// <param name="providerName"> provider name to be used. </param>
		/// <returns> the equivalent key with explicit curve parameters </returns>
		/// <exception cref="IllegalArgumentException"> </exception>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		public static PublicKey publicToExplicitParameters(PublicKey key, string providerName)
		{
			Provider provider = Security.getProvider(providerName);

			if (provider == null)
			{
				throw new NoSuchProviderException("cannot find provider: " + providerName);
			}

			return publicToExplicitParameters(key, provider);
		}

		/// <summary>
		/// Convert a passed in public EC key to have explicit parameters. If the key
		/// is already using explicit parameters it is returned.
		/// </summary>
		/// <param name="key"> key to be converted </param>
		/// <param name="provider"> provider to be used. </param>
		/// <returns> the equivalent key with explicit curve parameters </returns>
		/// <exception cref="IllegalArgumentException"> </exception>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		public static PublicKey publicToExplicitParameters(PublicKey key, Provider provider)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(key.getEncoded()));

				if (info.getAlgorithmId().getAlgorithm().Equals(CryptoProObjectIdentifiers_Fields.gostR3410_2001))
				{
					throw new IllegalArgumentException("cannot convert GOST key to explicit parameters.");
				}
				else
				{
					X962Parameters @params = X962Parameters.getInstance(info.getAlgorithmId().getParameters());
					X9ECParameters curveParams;

					if (@params.isNamedCurve())
					{
						ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());

						curveParams = ECUtil.getNamedCurveByOid(oid);
						// ignore seed value due to JDK bug
						curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());
					}
					else if (@params.isImplicitlyCA())
					{
						curveParams = new X9ECParameters(BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getG(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getN(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getH());
					}
					else
					{
						return key; // already explicit
					}

					@params = new X962Parameters(curveParams);

					info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), info.getPublicKeyData().getBytes());

					KeyFactory keyFact = KeyFactory.getInstance(key.getAlgorithm(), provider);

					return keyFact.generatePublic(new X509EncodedKeySpec(info.getEncoded()));
				}
			}
			catch (IllegalArgumentException e)
			{
				throw e;
			}
			catch (NoSuchAlgorithmException e)
			{
				throw e;
			}
			catch (Exception e)
			{ // shouldn't really happen...
				throw new UnexpectedException(e);
			}
		}

		/// <summary>
		/// Convert a passed in private EC key to have explicit parameters. If the key
		/// is already using explicit parameters it is returned.
		/// </summary>
		/// <param name="key"> key to be converted </param>
		/// <param name="providerName"> provider name to be used. </param>
		/// <returns> the equivalent key with explicit curve parameters </returns>
		/// <exception cref="IllegalArgumentException"> </exception>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		public static PrivateKey privateToExplicitParameters(PrivateKey key, string providerName)
		{
			Provider provider = Security.getProvider(providerName);

			if (provider == null)
			{
				throw new NoSuchProviderException("cannot find provider: " + providerName);
			}

			return privateToExplicitParameters(key, provider);
		}

		/// <summary>
		/// Convert a passed in private EC key to have explicit parameters. If the key
		/// is already using explicit parameters it is returned.
		/// </summary>
		/// <param name="key"> key to be converted </param>
		/// <param name="provider"> provider to be used. </param>
		/// <returns> the equivalent key with explicit curve parameters </returns>
		/// <exception cref="IllegalArgumentException"> </exception>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		public static PrivateKey privateToExplicitParameters(PrivateKey key, Provider provider)
		{
			try
			{
				PrivateKeyInfo info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(key.getEncoded()));

				if (info.getPrivateKeyAlgorithm().getAlgorithm().Equals(CryptoProObjectIdentifiers_Fields.gostR3410_2001))
				{
					throw new UnsupportedEncodingException("cannot convert GOST key to explicit parameters.");
				}
				else
				{
					X962Parameters @params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());
					X9ECParameters curveParams;

					if (@params.isNamedCurve())
					{
						ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());

						curveParams = ECUtil.getNamedCurveByOid(oid);
						// ignore seed value due to JDK bug
						curveParams = new X9ECParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH());
					}
					else if (@params.isImplicitlyCA())
					{
						curveParams = new X9ECParameters(BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getG(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getN(), BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getH());
					}
					else
					{
						return key; // already explicit
					}

					@params = new X962Parameters(curveParams);

					info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), info.parsePrivateKey());

					KeyFactory keyFact = KeyFactory.getInstance(key.getAlgorithm(), provider);

					return keyFact.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
				}
			}
			catch (IllegalArgumentException e)
			{
				throw e;
			}
			catch (NoSuchAlgorithmException e)
			{
				throw e;
			}
			catch (Exception e)
			{ // shouldn't really happen
				throw new UnexpectedException(e);
			}
		}

		public class UnexpectedException : RuntimeException
		{
			internal Exception cause;

			public UnexpectedException(Exception cause) : base(cause.ToString())
			{

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}