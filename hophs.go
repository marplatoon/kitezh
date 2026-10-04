package main

import "github.com/flynn/noise"

// хендшейк хопа цепочки: Noise_NK. У клиента нет статического ключа
// (хоп не узнаёт, кто он), ключ хопа клиент знает заранее

// hopInit - состояние клиента между msg1 и msg2
type hopInit struct {
	hs *noise.HandshakeState
}

// hopStart делает msg1 для хопа с закреплённым ключом peerKey
func hopStart(cs noise.CipherSuite, peerKey []byte) (*hopInit, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  peerKey,
	})
	if err != nil {
		return nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return &hopInit{hs}, msg1, nil
}

// finish принимает msg2 и достаёт ключи хопа
func (i *hopInit) finish(msg2 []byte) (*hop, error) {
	_, ir, ri, err := i.hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, err
	}
	return newHop(layerSecret(i.hs.ChannelBinding(), ir, ri))
}

// hopAnswer - сторона хопа: читает msg1, отдаёт msg2 и свои ключи
func hopAnswer(cs noise.CipherSuite, static noise.DHKey, msg1 []byte) ([]byte, *hop, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: static,
	})
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, err
	}
	msg2, ir, ri, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	h, err := newHop(layerSecret(hs.ChannelBinding(), ir, ri))
	if err != nil {
		return nil, nil, err
	}
	return msg2, h, nil
}
