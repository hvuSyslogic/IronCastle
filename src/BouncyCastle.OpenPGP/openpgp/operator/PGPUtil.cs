using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator
{

	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using S2K = org.bouncycastle.bcpg.S2K;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Basic utility class
	/// </summary>
	public class PGPUtil : HashAlgorithmTags
	{
		internal static byte[] makeKeyFromPassPhrase(PGPDigestCalculator digestCalculator, int algorithm, S2K s2k, char[] passPhrase)
		{
			// TODO: Never used
			string algName = null;
			int keySize = 0;

			switch (algorithm)
			{
			case SymmetricKeyAlgorithmTags_Fields.TRIPLE_DES:
				keySize = 192;
				algName = "DES_EDE";
				break;
			case SymmetricKeyAlgorithmTags_Fields.IDEA:
				keySize = 128;
				algName = "IDEA";
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAST5:
				keySize = 128;
				algName = "CAST5";
				break;
			case SymmetricKeyAlgorithmTags_Fields.BLOWFISH:
				keySize = 128;
				algName = "Blowfish";
				break;
			case SymmetricKeyAlgorithmTags_Fields.SAFER:
				keySize = 128;
				algName = "SAFER";
				break;
			case SymmetricKeyAlgorithmTags_Fields.DES:
				keySize = 64;
				algName = "DES";
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
				keySize = 128;
				algName = "AES";
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
				keySize = 192;
				algName = "AES";
				break;
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				keySize = 256;
				algName = "AES";
				break;
			case SymmetricKeyAlgorithmTags_Fields.TWOFISH:
				keySize = 256;
				algName = "Twofish";
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
				keySize = 128;
				algName = "Camellia";
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
				keySize = 192;
				algName = "Camellia";
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
				keySize = 256;
				algName = "Camellia";
				break;
			default:
				throw new PGPException("unknown symmetric algorithm: " + algorithm);
			}

			byte[] pBytes = Strings.toUTF8ByteArray(passPhrase);
			byte[] keyBytes = new byte[(keySize + 7) / 8];

			int generatedBytes = 0;
			int loopCount = 0;

			if (s2k != null)
			{
				if (s2k.getHashAlgorithm() != digestCalculator.getAlgorithm())
				{
					throw new PGPException("s2k/digestCalculator mismatch");
				}
			}
			else
			{
				if (digestCalculator.getAlgorithm() != HashAlgorithmTags_Fields.MD5)
				{
					throw new PGPException("digestCalculator not for MD5");
				}
			}

			OutputStream dOut = digestCalculator.getOutputStream();

			try
			{
				while (generatedBytes < keyBytes.Length)
				{
					if (s2k != null)
					{
						for (int i = 0; i != loopCount; i++)
						{
							dOut.write(0);
						}

						byte[] iv = s2k.getIV();

						switch (s2k.getType())
						{
						case S2K.SIMPLE:
							dOut.write(pBytes);
							break;
						case S2K.SALTED:
							dOut.write(iv);
							dOut.write(pBytes);
							break;
						case S2K.SALTED_AND_ITERATED:
							long count = s2k.getIterationCount();
							dOut.write(iv);
							dOut.write(pBytes);

							count -= iv.Length + pBytes.Length;

							while (count > 0)
							{
								if (count < iv.Length)
								{
									dOut.write(iv, 0, (int)count);
									break;
								}
								else
								{
									dOut.write(iv);
									count -= iv.Length;
								}

								if (count < pBytes.Length)
								{
									dOut.write(pBytes, 0, (int)count);
									count = 0;
								}
								else
								{
									dOut.write(pBytes);
									count -= pBytes.Length;
								}
							}
							break;
						default:
							throw new PGPException("unknown S2K type: " + s2k.getType());
						}
					}
					else
					{
						for (int i = 0; i != loopCount; i++)
						{
							dOut.write((byte)0);
						}

						dOut.write(pBytes);
					}

					dOut.close();

					byte[] dig = digestCalculator.getDigest();

					if (dig.Length > (keyBytes.Length - generatedBytes))
					{
						JavaSystem.arraycopy(dig, 0, keyBytes, generatedBytes, keyBytes.Length - generatedBytes);
					}
					else
					{
						JavaSystem.arraycopy(dig, 0, keyBytes, generatedBytes, dig.Length);
					}

					generatedBytes += dig.Length;

					loopCount++;
				}
			}
			catch (IOException e)
			{
				throw new PGPException("exception calculating digest: " + e.Message, e);
			}

			for (int i = 0; i != pBytes.Length; i++)
			{
				pBytes[i] = 0;
			}

			return keyBytes;
		}

		public static byte[] makeKeyFromPassPhrase(PGPDigestCalculatorProvider digCalcProvider, int algorithm, S2K s2k, char[] passPhrase)
		{
			PGPDigestCalculator digestCalculator;

			if (s2k != null)
			{
				digestCalculator = digCalcProvider.get(s2k.getHashAlgorithm());
			}
			else
			{
				digestCalculator = digCalcProvider.get(HashAlgorithmTags_Fields.MD5);
			}

			return makeKeyFromPassPhrase(digestCalculator, algorithm, s2k, passPhrase);
		}
	}

}