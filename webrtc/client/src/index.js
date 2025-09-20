const { useEffect, useRef } = React;

function App() {
  const remoteVideo = useRef(null);
  useEffect(() => {
    const pc = new RTCPeerConnection();
    pc.ontrack = (event) => {
      remoteVideo.current.srcObject = event.streams[0];
    };
    navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then(stream => {
      stream.getTracks().forEach(track => pc.addTrack(track, stream));
    });
  }, []);

  return React.createElement('div', null,
    React.createElement('h1', null, 'WebRTC Client'),
    React.createElement('video', { ref: remoteVideo, autoPlay: true, playsInline: true })
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
