using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using PacketTags = org.bouncycastle.bcpg.PacketTags;
	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// General class for reading a PGP object stream.
	/// <para>
	/// Note: if this class finds a <seealso cref="PGPPublicKey"/> or a <seealso cref="PGPSecretKey"/> it will create a
	/// <seealso cref="PGPPublicKeyRing"/>, or a <seealso cref="PGPSecretKeyRing"/> for each key found. If all you are trying
	/// to do is read a key ring file use either <seealso cref="PGPPublicKeyRingCollection"/> or
	/// <seealso cref="PGPSecretKeyRingCollection"/>.
	/// </para>
	/// </para><para>
	/// This factory supports reading the following types of objects: </p>
	/// <ul>
	/// <li><seealso cref="PacketTags#SIGNATURE"/> - produces a <seealso cref="PGPSignatureList"/></li>
	/// <li><seealso cref="PacketTags#SECRET_KEY"/> - produces a <seealso cref="PGPSecretKeyRing"/></li>
	/// <li><seealso cref="PacketTags#PUBLIC_KEY"/> - produces a <seealso cref="PGPPublicKeyRing"/></li>
	/// <li><seealso cref="PacketTags#PUBLIC_SUBKEY"/> - produces a <seealso cref="PGPPublicKey"/></li>
	/// <li><seealso cref="PacketTags#COMPRESSED_DATA"/> - produces a <seealso cref="PGPCompressedData"/></li>
	/// <li><seealso cref="PacketTags#LITERAL_DATA"/> - produces a <seealso cref="PGPLiteralData"/></li>
	/// <li><seealso cref="PacketTags#PUBLIC_KEY_ENC_SESSION"/> - produces a <seealso cref="PGPEncryptedDataList"/></li>
	/// <li><seealso cref="PacketTags#SYMMETRIC_KEY_ENC_SESSION"/> - produces a <seealso cref="PGPEncryptedDataList"/></li>
	/// <li><seealso cref="PacketTags#ONE_PASS_SIGNATURE"/> - produces a <seealso cref="PGPOnePassSignatureList"/></li>
	/// <li><seealso cref="PacketTags#MARKER"/> - produces a <seealso cref="PGPMarker"/></li>
	/// </ul>
	/// 
	/// </summary>
	public class PGPObjectFactory : Iterable
	{
		private BCPGInputStream @in;
		private KeyFingerPrintCalculator fingerPrintCalculator;

		/// <summary>
		/// Create an object factory suitable for reading PGP objects such as keys, key rings and key
		/// ring collections, or PGP encrypted data.
		/// </summary>
		/// <param name="in"> stream to read PGP data from. </param>
		/// <param name="fingerPrintCalculator"> calculator to use in key finger print calculations. </param>
		public PGPObjectFactory(InputStream @in, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			this.@in = new BCPGInputStream(@in);
			this.fingerPrintCalculator = fingerPrintCalculator;
		}

		/// <summary>
		/// Create an object factory suitable for reading PGP objects such as keys, key rings and key
		/// ring collections, or PGP encrypted data.
		/// </summary>
		/// <param name="bytes"> PGP encoded data. </param>
		/// <param name="fingerPrintCalculator"> calculator to use in key finger print calculations. </param>
		public PGPObjectFactory(byte[] bytes, KeyFingerPrintCalculator fingerPrintCalculator) : this(new ByteArrayInputStream(bytes), fingerPrintCalculator)
		{
		}

		/// <summary>
		/// Return the next object in the stream, or <code>null</code> if the end of stream is reached.
		/// </summary>
		/// <returns> one of the supported objects - see class docs for details. </returns>
		/// <exception cref="IOException"> if an error occurs reading from the wrapped stream or parsing data. </exception>
		public virtual object nextObject()
		{
			List l;

			switch (@in.nextPacketTag())
			{
			case -1:
				return null;
			case PacketTags_Fields.SIGNATURE:
				l = new ArrayList();

				while (@in.nextPacketTag() == PacketTags_Fields.SIGNATURE)
				{
					try
					{
						l.add(new PGPSignature(@in));
					}
					catch (PGPException e)
					{
						throw new IOException("can't create signature object: " + e);
					}
				}

				return new PGPSignatureList((PGPSignature[])l.toArray(new PGPSignature[l.size()]));
			case PacketTags_Fields.SECRET_KEY:
				try
				{
					return new PGPSecretKeyRing(@in, fingerPrintCalculator);
				}
				catch (PGPException e)
				{
					throw new IOException("can't create secret key object: " + e);
				}
			case PacketTags_Fields.PUBLIC_KEY:
				return new PGPPublicKeyRing(@in, fingerPrintCalculator);
			case PacketTags_Fields.PUBLIC_SUBKEY:
				try
				{
					return PGPPublicKeyRing.readSubkey(@in, fingerPrintCalculator);
				}
				catch (PGPException e)
				{
					throw new IOException("processing error: " + e.Message);
				}
			case PacketTags_Fields.COMPRESSED_DATA:
				return new PGPCompressedData(@in);
			case PacketTags_Fields.LITERAL_DATA:
				return new PGPLiteralData(@in);
			case PacketTags_Fields.PUBLIC_KEY_ENC_SESSION:
			case PacketTags_Fields.SYMMETRIC_KEY_ENC_SESSION:
				return new PGPEncryptedDataList(@in);
			case PacketTags_Fields.ONE_PASS_SIGNATURE:
				l = new ArrayList();

				while (@in.nextPacketTag() == PacketTags_Fields.ONE_PASS_SIGNATURE)
				{
					try
					{
						l.add(new PGPOnePassSignature(@in));
					}
					catch (PGPException e)
					{
						throw new IOException("can't create one pass signature object: " + e);
					}
				}

				return new PGPOnePassSignatureList((PGPOnePassSignature[])l.toArray(new PGPOnePassSignature[l.size()]));
			case PacketTags_Fields.MARKER:
				return new PGPMarker(@in);
			case PacketTags_Fields.EXPERIMENTAL_1:
			case PacketTags_Fields.EXPERIMENTAL_2:
			case PacketTags_Fields.EXPERIMENTAL_3:
			case PacketTags_Fields.EXPERIMENTAL_4:
				return @in.readPacket();
			}

			throw new IOException("unknown object in stream: " + @in.nextPacketTag());
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator iterator()
		{
			return new IteratorAnonymousInnerClass(this);
		}

		public class IteratorAnonymousInnerClass : Iterator
		{
			private readonly PGPObjectFactory outerInstance;

			public IteratorAnonymousInnerClass(PGPObjectFactory outerInstance)
			{
				this.outerInstance = outerInstance;
				triedNext = false;
				obj = null;
			}

			private bool triedNext;
			private object obj;

			public bool hasNext()
			{
				if (!triedNext)
				{
					triedNext = true;
					obj = getObject();
				}
				return obj != null;
			}

			public object next()
			{
				if (!hasNext())
				{
					throw new NoSuchElementException();
				}
				triedNext = false;

				return obj;
			}

			public void remove()
			{
				throw new UnsupportedOperationException("Cannot remove element from factory.");
			}

			private object getObject()
			{
				try
				{
					return outerInstance.nextObject();
				}
				catch (IOException e)
				{
					throw new PGPRuntimeOperationException("Iterator failed to get next object: " + e.Message, e);
				}
			}
		}
	}

}