namespace org.bouncycastle.mail.smime.util
{

	public class SharedFileInputStream : FilterInputStream, SharedInputStream
	{
		private readonly SharedFileInputStream _parent;
		private readonly File _file;
		private readonly long _start;
		private readonly long _length;

		private long _position;
		private long _markedPosition;

		private List _subStreams = new LinkedList();

		public SharedFileInputStream(string fileName) : this(new File(fileName))
		{
		}

		public SharedFileInputStream(File file) : this(file, 0, file.length())
		{
		}

		private SharedFileInputStream(File file, long start, long length) : base(new BufferedInputStream(new FileInputStream(file)))
		{

			_parent = null;
			_file = file;
			_start = start;
			_length = length;

			@in.skip(start);
		}

		private SharedFileInputStream(SharedFileInputStream parent, long start, long length) : base(new BufferedInputStream(new FileInputStream(parent._file)))
		{

			_parent = parent;
			_file = parent._file;
			_start = start;
			_length = length;

			@in.skip(start);
		}

		public virtual long getPosition()
		{
			return _position;
		}

		public virtual InputStream newStream(long start, long finish)
		{
			try
			{
				SharedFileInputStream stream;

				if (finish < 0)
				{
					if (_length > 0)
					{
						stream = new SharedFileInputStream(this, _start + start, _length - start);
					}
					else if (_length == 0)
					{
						stream = new SharedFileInputStream(this, _start + start, 0);
					}
					else
					{
						stream = new SharedFileInputStream(this, _start + start, -1);
					}
				}
				else
				{
					stream = new SharedFileInputStream(this, _start + start, finish - start);
				}

				_subStreams.add(stream);

				return stream;
			}
			catch (IOException e)
			{
				throw new IllegalStateException("unable to create shared stream: " + e);
			}
		}

		public virtual int read(byte[] buf)
		{
			return this.read(buf, 0, buf.Length);
		}

		public virtual int read(byte[] buf, int off, int len)
		{
			int count = 0;

			if (len == 0)
			{
				return 0;
			}

			while (count < len)
			{
				int ch = this.read();

				if (ch < 0)
				{
					break;
				}

				buf[off + count] = (byte)ch;
				count++;
			}

			if (count == 0)
			{
				return -1; // EOF
			}

			return count;
		}

		public virtual int read()
		{
			if (_position == _length)
			{
				return -1;
			}

			_position++;
			return @in.read();
		}

		public virtual bool markSupported()
		{
			return true;
		}

		public virtual long skip(long n)
		{
			long count;

			for (count = 0; count != n; count++)
			{
				if (this.read() < 0)
				{
					break;
				}
			}

			return count;
		}

		public virtual void mark(int readLimit)
		{
			_markedPosition = _position;
			@in.mark(readLimit);
		}

		public virtual void reset()
		{
			_position = _markedPosition;
			@in.reset();
		}

		/// <summary>
		/// Return the shared stream that represents the top most stream that
		/// this stream inherits from. </summary>
		/// <returns>  the base of the shared stream tree. </returns>
		public virtual SharedFileInputStream getRoot()
		{
			if (_parent != null)
			{
				return _parent.getRoot();
			}

			return this;
		}

		/// <summary>
		/// Close of this stream and any substreams that have been created from it. </summary>
		/// <exception cref="IOException"> on problem closing the main stream. </exception>
		public virtual void dispose()
		{
			Iterator it = _subStreams.iterator();

			while (it.hasNext())
			{
				try
				{
					((SharedFileInputStream)it.next()).dispose();
				}
				catch (IOException)
				{
					// ignore
				}
			}

			@in.close();
		}
	}

}