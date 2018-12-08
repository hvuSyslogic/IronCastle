using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.digests
{

	using ThreefishEngine = org.bouncycastle.crypto.engines.ThreefishEngine;
	using SkeinMac = org.bouncycastle.crypto.macs.SkeinMac;
	using SkeinParameters = org.bouncycastle.crypto.@params.SkeinParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// Implementation of the Skein family of parameterised hash functions in 256, 512 and 1024 bit block
	/// sizes, based on the <seealso cref="ThreefishEngine Threefish"/> tweakable block cipher.
	/// <para>
	/// This is the 1.3 version of Skein defined in the Skein hash function submission to the NIST SHA-3
	/// competition in October 2010.
	/// </para>
	/// <para>
	/// Skein was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
	/// Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
	/// </para>
	/// <para>
	/// This implementation is the basis for <seealso cref="SkeinDigest"/> and <seealso cref="SkeinMac"/>, implementing the
	/// parameter based configuration system that allows Skein to be adapted to multiple applications. <br>
	/// Initialising the engine with <seealso cref="SkeinParameters"/> allows standard and arbitrary parameters to
	/// be applied during the Skein hash function.
	/// </para>
	/// <para>
	/// Implemented:
	/// <ul>
	/// <li>256, 512 and 1024 bit internal states.</li>
	/// <li>Full 96 bit input length.</li>
	/// <li>Parameters defined in the Skein specification, and arbitrary other pre and post message
	/// parameters.</li>
	/// <li>Arbitrary output size in 1 byte intervals.</li>
	/// </ul>
	/// </para>
	/// <para>
	/// Not implemented:
	/// <ul>
	/// <li>Sub-byte length input (bit padding).</li>
	/// <li>Tree hashing.</li>
	/// </ul>
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SkeinParameters </seealso>
	public class SkeinEngine : Memoable
	{
		/// <summary>
		/// 256 bit block size - Skein 256
		/// </summary>
		public const int SKEIN_256 = ThreefishEngine.BLOCKSIZE_256;
		/// <summary>
		/// 512 bit block size - Skein 512
		/// </summary>
		public const int SKEIN_512 = ThreefishEngine.BLOCKSIZE_512;
		/// <summary>
		/// 1024 bit block size - Skein 1024
		/// </summary>
		public const int SKEIN_1024 = ThreefishEngine.BLOCKSIZE_1024;

		// Minimal at present, but more complex when tree hashing is implemented
		public class Configuration
		{
			internal byte[] bytes = new byte[32];

			public Configuration(long outputSizeBits)
			{
				// 0..3 = ASCII SHA3
				bytes[0] = (byte)'S';
				bytes[1] = (byte)'H';
				bytes[2] = (byte)'A';
				bytes[3] = (byte)'3';

				// 4..5 = version number in LSB order
				bytes[4] = 1;
				bytes[5] = 0;

				// 8..15 = output length
				ThreefishEngine.wordToBytes(outputSizeBits, bytes, 8);
			}

			public virtual byte[] getBytes()
			{
				return bytes;
			}

		}

		public class Parameter
		{
			internal int type;
			internal byte[] value;

			public Parameter(int type, byte[] value)
			{
				this.type = type;
				this.value = value;
			}

			public virtual int getType()
			{
				return type;
			}

			public virtual byte[] getValue()
			{
				return value;
			}

		}

		/// <summary>
		/// The parameter type for the Skein key.
		/// </summary>
		private const int PARAM_TYPE_KEY = 0;

		/// <summary>
		/// The parameter type for the Skein configuration block.
		/// </summary>
		private const int PARAM_TYPE_CONFIG = 4;

		/// <summary>
		/// The parameter type for the message.
		/// </summary>
		private const int PARAM_TYPE_MESSAGE = 48;

		/// <summary>
		/// The parameter type for the output transformation.
		/// </summary>
		private const int PARAM_TYPE_OUTPUT = 63;

		/// <summary>
		/// Precalculated UBI(CFG) states for common state/output combinations without key or other
		/// pre-message params.
		/// </summary>
		private static readonly Hashtable INITIAL_STATES = new Hashtable();

		static SkeinEngine()
		{
			// From Appendix C of the Skein 1.3 NIST submission
			initialState(SKEIN_256, 128, new long[]{unchecked((long)0xe1111906964d7260L), unchecked((long)0x883daaa77c8d811cL), 0x10080df491960f7aL, unchecked((long)0xccf7dde5b45bc1c2L)});

			initialState(SKEIN_256, 160, new long[]{0x1420231472825e98L, 0x2ac4e9a25a77e590L, unchecked((long)0xd47a58568838d63eL), 0x2dd2e4968586ab7dL});

			initialState(SKEIN_256, 224, new long[]{unchecked((long)0xc6098a8c9ae5ea0bL), unchecked((long)0x876d568608c5191cL), unchecked((long)0x99cb88d7d7f53884L), 0x384bddb1aeddb5deL});

			initialState(SKEIN_256, 256, new long[]{unchecked((long)0xfc9da860d048b449L), 0x2fca66479fa7d833L, unchecked((long)0xb33bc3896656840fL), 0x6a54e920fde8da69L});

			initialState(SKEIN_512, 128, new long[]{unchecked((long)0xa8bc7bf36fbf9f52L), 0x1e9872cebd1af0aaL, 0x309b1790b32190d3L, unchecked((long)0xbcfbb8543f94805cL), 0x0da61bcd6e31b11bL, 0x1a18ebead46a32e3L, unchecked((long)0xa2cc5b18ce84aa82L), 0x6982ab289d46982dL});

			initialState(SKEIN_512, 160, new long[]{0x28b81a2ae013bd91L, unchecked((long)0xc2f11668b5bdf78fL), 0x1760d8f3f6a56f12L, 0x4fb747588239904fL, 0x21ede07f7eaf5056L, unchecked((long)0xd908922e63ed70b8L), unchecked((long)0xb8ec76ffeccb52faL), 0x01a47bb8a3f27a6eL});

			initialState(SKEIN_512, 224, new long[]{unchecked((long)0xccd0616248677224L), unchecked((long)0xcba65cf3a92339efL), unchecked((long)0x8ccd69d652ff4b64L), 0x398aed7b3ab890b4L, 0x0f59d1b1457d2bd0L, 0x6776fe6575d4eb3dL, unchecked((long)0x99fbc70e997413e9L), unchecked((long)0x9e2cfccfe1c41ef7L)});

			initialState(SKEIN_512, 384, new long[]{unchecked((long)0xa3f6c6bf3a75ef5fL), unchecked((long)0xb0fef9ccfd84faa4L), unchecked((long)0x9d77dd663d770cfeL), unchecked((long)0xd798cbf3b468fddaL), 0x1bc4a6668a0e4465L, 0x7ed7d434e5807407L, 0x548fc1acd4ec44d6L, 0x266e17546aa18ff8L});

			initialState(SKEIN_512, 512, new long[]{0x4903adff749c51ceL, 0x0d95de399746df03L, unchecked((long)0x8fd1934127c79bceL), unchecked((long)0x9a255629ff352cb1L), 0x5db62599df6ca7b0L, unchecked((long)0xeabe394ca9d5c3f4L), unchecked((long)0x991112c71a75b523L), unchecked((long)0xae18a40b660fcc33L)});
		}

		private static void initialState(int blockSize, int outputSize, long[] state)
		{
			INITIAL_STATES.put(variantIdentifier(blockSize / 8, outputSize / 8), state);
		}

		private static int? variantIdentifier(int blockSizeBytes, int outputSizeBytes)
		{
			return Integers.valueOf((outputSizeBytes << 16) | blockSizeBytes);
		}

		public class UbiTweak
		{
			/// <summary>
			/// Point at which position might overflow long, so switch to add with carry logic
			/// </summary>
			internal static readonly long LOW_RANGE = long.MaxValue - int.MaxValue;

			/// <summary>
			/// Bit 127 = final
			/// </summary>
			internal static readonly long T1_FINAL = 1L << 63;

			/// <summary>
			/// Bit 126 = first
			/// </summary>
			internal static readonly long T1_FIRST = 1L << 62;

			/// <summary>
			/// UBI uses a 128 bit tweak
			/// </summary>
			internal long[] tweak = new long[2];

			/// <summary>
			/// Whether 64 bit position exceeded
			/// </summary>
			internal bool extendedPosition;

			public UbiTweak()
			{
				reset();
			}

			public virtual void reset(UbiTweak tweak)
			{
				this.tweak = Arrays.clone(tweak.tweak, this.tweak);
				this.extendedPosition = tweak.extendedPosition;
			}

			public virtual void reset()
			{
				tweak[0] = 0;
				tweak[1] = 0;
				extendedPosition = false;
				setFirst(true);
			}

			public virtual void setType(int type)
			{
				// Bits 120..125 = type
				tweak[1] = (tweak[1] & unchecked((long)0xFFFFFFC000000000L)) | ((type & 0x3FL) << 56);
			}

			public virtual int getType()
			{
				return (int)(((long)((ulong)tweak[1] >> 56)) & 0x3FL);
			}

			public virtual void setFirst(bool first)
			{
				if (first)
				{
					tweak[1] |= T1_FIRST;
				}
				else
				{
					tweak[1] &= ~T1_FIRST;
				}
			}

			public virtual bool isFirst()
			{
				return ((tweak[1] & T1_FIRST) != 0);
			}

			public virtual void setFinal(bool last)
			{
				if (last)
				{
					tweak[1] |= T1_FINAL;
				}
				else
				{
					tweak[1] &= ~T1_FINAL;
				}
			}

			public virtual bool isFinal()
			{
				return ((tweak[1] & T1_FINAL) != 0);
			}

			/// <summary>
			/// Advances the position in the tweak by the specified value.
			/// </summary>
			public virtual void advancePosition(int advance)
			{
				// Bits 0..95 = position
				if (extendedPosition)
				{
					long[] parts = new long[3];
					parts[0] = tweak[0] & 0xFFFFFFFFL;
					parts[1] = ((long)((ulong)tweak[0] >> 32)) & 0xFFFFFFFFL;
					parts[2] = tweak[1] & 0xFFFFFFFFL;

					long carry = advance;
					for (int i = 0; i < parts.Length; i++)
					{
						carry += parts[i];
						parts[i] = carry;
						carry = (long)((ulong)carry >> 32);
					}
					tweak[0] = ((parts[1] & 0xFFFFFFFFL) << 32) | (parts[0] & 0xFFFFFFFFL);
					tweak[1] = (tweak[1] & unchecked((long)0xFFFFFFFF00000000L)) | (parts[2] & 0xFFFFFFFFL);
				}
				else
				{
					long position = tweak[0];
					position += advance;
					tweak[0] = position;
					if (position > LOW_RANGE)
					{
						extendedPosition = true;
					}
				}
			}

			public virtual long[] getWords()
			{
				return tweak;
			}

			public override string ToString()
			{
				return getType() + " first: " + isFirst() + ", final: " + isFinal();
			}

		}

		/// <summary>
		/// The Unique Block Iteration chaining mode.
		/// </summary>
		// TODO: This might be better as methods...
		public class UBI
		{
			private readonly SkeinEngine outerInstance;

			internal readonly UbiTweak tweak = new UbiTweak();

			/// <summary>
			/// Buffer for the current block of message data
			/// </summary>
			internal byte[] currentBlock;

			/// <summary>
			/// Offset into the current message block
			/// </summary>
			internal int currentOffset;

			/// <summary>
			/// Buffer for message words for feedback into encrypted block
			/// </summary>
			internal long[] message;

			public UBI(SkeinEngine outerInstance, int blockSize)
			{
				this.outerInstance = outerInstance;
				currentBlock = new byte[blockSize];
				message = new long[currentBlock.Length / 8];
			}

			public virtual void reset(UBI ubi)
			{
				currentBlock = Arrays.clone(ubi.currentBlock, currentBlock);
				currentOffset = ubi.currentOffset;
				message = Arrays.clone(ubi.message, this.message);
				tweak.reset(ubi.tweak);
			}

			public virtual void reset(int type)
			{
				tweak.reset();
				tweak.setType(type);
				currentOffset = 0;
			}

			public virtual void update(byte[] value, int offset, int len, long[] output)
			{
				/*
				 * Buffer complete blocks for the underlying Threefish cipher, only flushing when there
				 * are subsequent bytes (last block must be processed in doFinal() with final=true set).
				 */
				int copied = 0;
				while (len > copied)
				{
					if (currentOffset == currentBlock.Length)
					{
						processBlock(output);
						tweak.setFirst(false);
						currentOffset = 0;
					}

					int toCopy = Math.Min((len - copied), currentBlock.Length - currentOffset);
					JavaSystem.arraycopy(value, offset + copied, currentBlock, currentOffset, toCopy);
					copied += toCopy;
					currentOffset += toCopy;
					tweak.advancePosition(toCopy);
				}
			}

			public virtual void processBlock(long[] output)
			{
				outerInstance.threefish.init(true, outerInstance.chain, tweak.getWords());
				for (int i = 0; i < message.Length; i++)
				{
					message[i] = ThreefishEngine.bytesToWord(currentBlock, i * 8);
				}

				outerInstance.threefish.processBlock(message, output);

				for (int i = 0; i < output.Length; i++)
				{
					output[i] ^= message[i];
				}
			}

			public virtual void doFinal(long[] output)
			{
				// Pad remainder of current block with zeroes
				for (int i = currentOffset; i < currentBlock.Length; i++)
				{
					currentBlock[i] = 0;
				}

				tweak.setFinal(true);
				processBlock(output);
			}

		}

		/// <summary>
		/// Underlying Threefish tweakable block cipher
		/// </summary>
		internal readonly ThreefishEngine threefish;

		/// <summary>
		/// Size of the digest output, in bytes
		/// </summary>
		private readonly int outputSizeBytes;

		/// <summary>
		/// The current chaining/state value
		/// </summary>
		internal long[] chain;

		/// <summary>
		/// The initial state value
		/// </summary>
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private long[] initialState_Renamed;

		/// <summary>
		/// The (optional) key parameter
		/// </summary>
		private byte[] key;

		/// <summary>
		/// Parameters to apply prior to the message
		/// </summary>
		private Parameter[] preMessageParameters;

		/// <summary>
		/// Parameters to apply after the message, but prior to output
		/// </summary>
		private Parameter[] postMessageParameters;

		/// <summary>
		/// The current UBI operation
		/// </summary>
		private readonly UBI ubi;

		/// <summary>
		/// Buffer for single byte update method
		/// </summary>
		private readonly byte[] singleByte = new byte[1];

		/// <summary>
		/// Constructs a Skein engine.
		/// </summary>
		/// <param name="blockSizeBits">  the internal state size in bits - one of <seealso cref="#SKEIN_256"/>, <seealso cref="#SKEIN_512"/> or
		///                       <seealso cref="#SKEIN_1024"/>. </param>
		/// <param name="outputSizeBits"> the output/digest size to produce in bits, which must be an integral number of
		///                       bytes. </param>
		public SkeinEngine(int blockSizeBits, int outputSizeBits)
		{
			if (outputSizeBits % 8 != 0)
			{
				throw new IllegalArgumentException("Output size must be a multiple of 8 bits. :" + outputSizeBits);
			}
			// TODO: Prevent digest sizes > block size?
			this.outputSizeBytes = outputSizeBits / 8;

			this.threefish = new ThreefishEngine(blockSizeBits);
			this.ubi = new UBI(this, threefish.getBlockSize());
		}

		/// <summary>
		/// Creates a SkeinEngine as an exact copy of an existing instance.
		/// </summary>
		public SkeinEngine(SkeinEngine engine) : this(engine.getBlockSize() * 8, engine.getOutputSize() * 8)
		{
			copyIn(engine);
		}

		private void copyIn(SkeinEngine engine)
		{
			this.ubi.reset(engine.ubi);
			this.chain = Arrays.clone(engine.chain, this.chain);
			this.initialState_Renamed = Arrays.clone(engine.initialState_Renamed, this.initialState_Renamed);
			this.key = Arrays.clone(engine.key, this.key);
			this.preMessageParameters = clone(engine.preMessageParameters, this.preMessageParameters);
			this.postMessageParameters = clone(engine.postMessageParameters, this.postMessageParameters);
		}

		private static Parameter[] clone(Parameter[] data, Parameter[] existing)
		{
			if (data == null)
			{
				return null;
			}
			if ((existing == null) || (existing.Length != data.Length))
			{
				existing = new Parameter[data.Length];
			}
			JavaSystem.arraycopy(data, 0, existing, 0, existing.Length);
			return existing;
		}

		public virtual Memoable copy()
		{
			return new SkeinEngine(this);
		}

		public virtual void reset(Memoable other)
		{
			SkeinEngine s = (SkeinEngine)other;
			if ((getBlockSize() != s.getBlockSize()) || (outputSizeBytes != s.outputSizeBytes))
			{
				throw new IllegalArgumentException("Incompatible parameters in provided SkeinEngine.");
			}
			copyIn(s);
		}

		public virtual int getOutputSize()
		{
			return outputSizeBytes;
		}

		public virtual int getBlockSize()
		{
			return threefish.getBlockSize();
		}

		/// <summary>
		/// Initialises the Skein engine with the provided parameters. See <seealso cref="SkeinParameters"/> for
		/// details on the parameterisation of the Skein hash function.
		/// </summary>
		/// <param name="params"> the parameters to apply to this engine, or <code>null</code> to use no parameters. </param>
		public virtual void init(SkeinParameters @params)
		{
			this.chain = null;
			this.key = null;
			this.preMessageParameters = null;
			this.postMessageParameters = null;

			if (@params != null)
			{
				byte[] key = @params.getKey();
				if (key.Length < 16)
				{
					throw new IllegalArgumentException("Skein key must be at least 128 bits.");
				}
				initParams(@params.getParameters());
			}
			createInitialState();

			// Initialise message block
			ubiInit(PARAM_TYPE_MESSAGE);
		}

		private void initParams(Hashtable parameters)
		{
			Enumeration keys = parameters.keys();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.Vector pre = new java.util.Vector();
			Vector pre = new Vector();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.Vector post = new java.util.Vector();
			Vector post = new Vector();

			while (keys.hasMoreElements())
			{
				int? type = (int?)keys.nextElement();
				byte[] value = (byte[])parameters.get(type);

				if (type.Value == PARAM_TYPE_KEY)
				{
					this.key = value;
				}
				else if (type.Value < PARAM_TYPE_MESSAGE)
				{
					pre.addElement(new Parameter(type.Value, value));
				}
				else
				{
					post.addElement(new Parameter(type.Value, value));
				}
			}
			preMessageParameters = new Parameter[pre.size()];
			pre.copyInto(preMessageParameters);
			sort(preMessageParameters);

			postMessageParameters = new Parameter[post.size()];
			post.copyInto(postMessageParameters);
			sort(postMessageParameters);
		}

		private static void sort(Parameter[] @params)
		{
			if (@params == null)
			{
				return;
			}
			// Insertion sort, for Java 1.1 compatibility
			for (int i = 1; i < @params.Length; i++)
			{
				Parameter param = @params[i];
				int hole = i;
				while (hole > 0 && param.getType() < @params[hole - 1].getType())
				{
					@params[hole] = @params[hole - 1];
					hole = hole - 1;
				}
				@params[hole] = param;
			}
		}

		/// <summary>
		/// Calculate the initial (pre message block) chaining state.
		/// </summary>
		private void createInitialState()
		{
			long[] precalc = (long[])INITIAL_STATES.get(variantIdentifier(getBlockSize(), getOutputSize()));
			if ((key == null) && (precalc != null))
			{
				// Precalculated UBI(CFG)
				chain = Arrays.clone(precalc);
			}
			else
			{
				// Blank initial state
				chain = new long[getBlockSize() / 8];

				// Process key block
				if (key != null)
				{
					ubiComplete(SkeinParameters.PARAM_TYPE_KEY, key);
				}

				// Process configuration block
				ubiComplete(PARAM_TYPE_CONFIG, (new Configuration(outputSizeBytes * 8)).getBytes());
			}

			// Process additional pre-message parameters
			if (preMessageParameters != null)
			{
				for (int i = 0; i < preMessageParameters.Length; i++)
				{
					Parameter param = preMessageParameters[i];
					ubiComplete(param.getType(), param.getValue());
				}
			}
			initialState_Renamed = Arrays.clone(chain);
		}

		/// <summary>
		/// Reset the engine to the initial state (with the key and any pre-message parameters , ready to
		/// accept message input.
		/// </summary>
		public virtual void reset()
		{
			JavaSystem.arraycopy(initialState_Renamed, 0, chain, 0, chain.Length);

			ubiInit(PARAM_TYPE_MESSAGE);
		}

		private void ubiComplete(int type, byte[] value)
		{
			ubiInit(type);
			this.ubi.update(value, 0, value.Length, chain);
			ubiFinal();
		}

		private void ubiInit(int type)
		{
			this.ubi.reset(type);
		}

		private void ubiFinal()
		{
			ubi.doFinal(chain);
		}

		private void checkInitialised()
		{
			if (this.ubi == null)
			{
				throw new IllegalArgumentException("Skein engine is not initialised.");
			}
		}

		public virtual void update(byte @in)
		{
			singleByte[0] = @in;
			update(singleByte, 0, 1);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			checkInitialised();
			ubi.update(@in, inOff, len, chain);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			checkInitialised();
			if (@out.Length < (outOff + outputSizeBytes))
			{
				throw new OutputLengthException("Output buffer is too short to hold output");
			}

			// Finalise message block
			ubiFinal();

			// Process additional post-message parameters
			if (postMessageParameters != null)
			{
				for (int i = 0; i < postMessageParameters.Length; i++)
				{
					Parameter param = postMessageParameters[i];
					ubiComplete(param.getType(), param.getValue());
				}
			}

			// Perform the output transform
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int blockSize = getBlockSize();
			int blockSize = getBlockSize();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int blocksRequired = ((outputSizeBytes + blockSize - 1) / blockSize);
			int blocksRequired = ((outputSizeBytes + blockSize - 1) / blockSize);
			for (int i = 0; i < blocksRequired; i++)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int toWrite = Math.Min(blockSize, outputSizeBytes - (i * blockSize));
				int toWrite = Math.Min(blockSize, outputSizeBytes - (i * blockSize));
				output(i, @out, outOff + (i * blockSize), toWrite);
			}

			reset();

			return outputSizeBytes;
		}

		private void output(long outputSequence, byte[] @out, int outOff, int outputBytes)
		{
			byte[] currentBytes = new byte[8];
			ThreefishEngine.wordToBytes(outputSequence, currentBytes, 0);

			// Output is a sequence of UBI invocations all of which use and preserve the pre-output
			// state
			long[] outputWords = new long[chain.Length];
			ubiInit(PARAM_TYPE_OUTPUT);
			this.ubi.update(currentBytes, 0, currentBytes.Length, outputWords);
			ubi.doFinal(outputWords);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final int wordsRequired = ((outputBytes + 8 - 1) / 8);
			int wordsRequired = ((outputBytes + 8 - 1) / 8);
			for (int i = 0; i < wordsRequired; i++)
			{
				int toWrite = Math.Min(8, outputBytes - (i * 8));
				if (toWrite == 8)
				{
					ThreefishEngine.wordToBytes(outputWords[i], @out, outOff + (i * 8));
				}
				else
				{
					ThreefishEngine.wordToBytes(outputWords[i], currentBytes, 0);
					JavaSystem.arraycopy(currentBytes, 0, @out, outOff + (i * 8), toWrite);
				}
			}
		}

	}

}