using System;

namespace org.bouncycastle.openpgp
{

	using PublicSubkeyPacket = org.bouncycastle.bcpg.PublicSubkeyPacket;
	using PBESecretKeyEncryptor = org.bouncycastle.openpgp.@operator.PBESecretKeyEncryptor;
	using PGPContentSignerBuilder = org.bouncycastle.openpgp.@operator.PGPContentSignerBuilder;
	using PGPDigestCalculator = org.bouncycastle.openpgp.@operator.PGPDigestCalculator;

	/// <summary>
	/// Generator for a PGP master and subkey ring. This class will generate
	/// both the secret and public key rings
	/// </summary>
	public class PGPKeyRingGenerator
	{
		internal List keys = new ArrayList();

		private PBESecretKeyEncryptor keyEncryptor;
		private PGPDigestCalculator checksumCalculator;
		private PGPKeyPair masterKey;
		private PGPSignatureSubpacketVector hashedPcks;
		private PGPSignatureSubpacketVector unhashedPcks;
		private PGPContentSignerBuilder keySignerBuilder;

		/// <summary>
		/// Create a new key ring generator.
		/// </summary>
		/// <param name="certificationLevel"> </param>
		/// <param name="masterKey"> </param>
		/// <param name="id"> </param>
		/// <param name="checksumCalculator"> </param>
		/// <param name="hashedPcks"> </param>
		/// <param name="unhashedPcks"> </param>
		/// <param name="keySignerBuilder"> </param>
		/// <param name="keyEncryptor"> </param>
		/// <exception cref="PGPException"> </exception>
		public PGPKeyRingGenerator(int certificationLevel, PGPKeyPair masterKey, string id, PGPDigestCalculator checksumCalculator, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks, PGPContentSignerBuilder keySignerBuilder, PBESecretKeyEncryptor keyEncryptor)
		{
			this.masterKey = masterKey;
			this.keyEncryptor = keyEncryptor;
			this.checksumCalculator = checksumCalculator;
			this.keySignerBuilder = keySignerBuilder;
			this.hashedPcks = hashedPcks;
			this.unhashedPcks = unhashedPcks;

			keys.add(new PGPSecretKey(certificationLevel, masterKey, id, checksumCalculator, hashedPcks, unhashedPcks, keySignerBuilder, keyEncryptor));
		}

		/// <summary>
		/// Add a sub key to the key ring to be generated with default certification and inheriting
		/// the hashed/unhashed packets of the master key.
		/// </summary>
		/// <param name="keyPair"> </param>
		/// <exception cref="PGPException"> </exception>
		public virtual void addSubKey(PGPKeyPair keyPair)
		{
			addSubKey(keyPair, hashedPcks, unhashedPcks);
		}

		/// <summary>
		/// Add a subkey with specific hashed and unhashed packets associated with it and default
		/// certification. 
		/// </summary>
		/// <param name="keyPair"> public/private key pair. </param>
		/// <param name="hashedPcks"> hashed packet values to be included in certification. </param>
		/// <param name="unhashedPcks"> unhashed packets values to be included in certification. </param>
		/// <exception cref="PGPException"> </exception>
		public virtual void addSubKey(PGPKeyPair keyPair, PGPSignatureSubpacketVector hashedPcks, PGPSignatureSubpacketVector unhashedPcks)
		{
			try
			{
				//
				// generate the certification
				//
				PGPSignatureGenerator sGen = new PGPSignatureGenerator(keySignerBuilder);

				sGen.init(PGPSignature.SUBKEY_BINDING, masterKey.getPrivateKey());

				sGen.setHashedSubpackets(hashedPcks);
				sGen.setUnhashedSubpackets(unhashedPcks);

				List subSigs = new ArrayList();

				subSigs.add(sGen.generateCertification(masterKey.getPublicKey(), keyPair.getPublicKey()));

				// replace the public key packet structure with a public subkey one.
				PGPPublicKey pubSubKey = new PGPPublicKey(keyPair.getPublicKey(), null, subSigs);

				pubSubKey.publicPk = new PublicSubkeyPacket(pubSubKey.getAlgorithm(), pubSubKey.getCreationTime(), pubSubKey.publicPk.getKey());

				keys.add(new PGPSecretKey(keyPair.getPrivateKey(), pubSubKey, checksumCalculator, keyEncryptor));
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("exception adding subkey: ", e);
			}
		}

		/// <summary>
		/// Return the secret key ring.
		/// </summary>
		/// <returns> a secret key ring. </returns>
		public virtual PGPSecretKeyRing generateSecretKeyRing()
		{
			return new PGPSecretKeyRing(keys);
		}

		/// <summary>
		/// Return the public key ring that corresponds to the secret key ring.
		/// </summary>
		/// <returns> a public key ring. </returns>
		public virtual PGPPublicKeyRing generatePublicKeyRing()
		{
			Iterator it = keys.iterator();
			List pubKeys = new ArrayList();

			pubKeys.add(((PGPSecretKey)it.next()).getPublicKey());

			while (it.hasNext())
			{
				pubKeys.add(((PGPSecretKey)it.next()).getPublicKey());
			}

			return new PGPPublicKeyRing(pubKeys);
		}
	}

}