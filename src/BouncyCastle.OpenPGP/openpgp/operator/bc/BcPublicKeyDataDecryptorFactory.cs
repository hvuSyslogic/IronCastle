namespace org.bouncycastle.openpgp.@operator.bc
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using ECSecretBCPGKey = org.bouncycastle.bcpg.ECSecretBCPGKey;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedAsymmetricBlockCipher = org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// A decryptor factory for handling public key decryption operations.
	/// </summary>
	public class BcPublicKeyDataDecryptorFactory : PublicKeyDataDecryptorFactory
	{
		private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();
		private PGPPrivateKey privKey;

		public BcPublicKeyDataDecryptorFactory(PGPPrivateKey privKey)
		{
			this.privKey = privKey;
		}

		public virtual byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
		{
			try
			{
				if (keyAlgorithm != PGPPublicKey.ECDH)
				{
					AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

					AsymmetricKeyParameter key = keyConverter.getPrivateKey(privKey);

					BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

					c1.init(false, key);

					if (keyAlgorithm == PGPPublicKey.RSA_ENCRYPT || keyAlgorithm == PGPPublicKey.RSA_GENERAL)
					{
						byte[] bi = secKeyData[0];

						c1.processBytes(bi, 2, bi.Length - 2);
					}
					else
					{
						BcPGPKeyConverter converter = new BcPGPKeyConverter();
						ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters)converter.getPrivateKey(privKey);
						int size = (parms.getParameters().getP().bitLength() + 7) / 8;
						byte[] tmp = new byte[size];

						byte[] bi = secKeyData[0]; // encoded MPI
						if (bi.Length - 2 > size) // leading Zero? Shouldn't happen but...
						{
							c1.processBytes(bi, 3, bi.Length - 3);
						}
						else
						{
							JavaSystem.arraycopy(bi, 2, tmp, tmp.Length - (bi.Length - 2), bi.Length - 2);
							c1.processBytes(tmp, 0, tmp.Length);
						}

						bi = secKeyData[1]; // encoded MPI
						for (int i = 0; i != tmp.Length; i++)
						{
							tmp[i] = 0;
						}

						if (bi.Length - 2 > size) // leading Zero? Shouldn't happen but...
						{
							c1.processBytes(bi, 3, bi.Length - 3);
						}
						else
						{
							JavaSystem.arraycopy(bi, 2, tmp, tmp.Length - (bi.Length - 2), bi.Length - 2);
							c1.processBytes(tmp, 0, tmp.Length);
						}
					}

					return c1.doFinal();
				}
				else
				{
					ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)privKey.getPublicKeyPacket().getKey();
					X9ECParameters x9Params = ECNamedCurveTable.getByOID(ecKey.getCurveOID());

					byte[] enc = secKeyData[0];

					int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
					byte[] pEnc = new byte[pLen];

					JavaSystem.arraycopy(enc, 2, pEnc, 0, pLen);

					byte[] keyEnc = new byte[enc[pLen + 2]];

					JavaSystem.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

					Wrapper c = BcImplProvider.createWrapper(ecKey.getSymmetricKeyAlgorithm());

					ECPoint S = x9Params.getCurve().decodePoint(pEnc).multiply(((ECSecretBCPGKey)privKey.getPrivateKeyDataPacket()).getX()).normalize();

					RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator((new BcPGPDigestCalculatorProvider()).get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());
					KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(S, RFC6637Utils.createUserKeyingMaterial(privKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator())));

					c.init(false, key);

					return PGPPad.unpadSessionData(c.unwrap(keyEnc, 0, keyEnc.Length));
				}
			}
			catch (IOException e)
			{
				throw new PGPException("exception creating user keying material: " + e.Message, e);
			}
			catch (InvalidCipherTextException e)
			{
				throw new PGPException("exception decrypting session info: " + e.Message, e);
			}

		}

		public virtual PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
		{
			BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

			return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
		}
	}

}