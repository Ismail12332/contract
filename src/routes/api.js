const express = require('express');
const supabase = require('../db/connect');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const { s3, BUCKET_NAME } = require('../db/vultr');

const router = express.Router();

// Настройка JWKS клиента
const jwksClient = jwksRsa({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
});

// Функция для получения ключа
const getKey = (header, callback) => {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err, null);
    } else {
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    }
  });
};


const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() }); // Используем память для хранения файла перед загрузкой в Vultr


router.get('/search-options', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('search_options')
      .select('*')
      .order('value', { ascending: true });

    if (error) {
      console.error('Error fetching search options:', error);
      return res.status(500).json({ message: 'Failed to fetch search options' });
    }

    res.status(200).json(data);
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


router.get('/companies', async (req, res) => {
  try {
    // Получаем компании со статусом "active" и доступностью "true"
    const { data, error } = await supabase
      .from('companies')
      .select('*')
      .eq('status', 'active')
      .eq('available', true);

    if (error) {
      console.error('Error fetching companies:', error);
      return res.status(500).json({ message: 'Failed to fetch companies' });
    }

    res.status(200).json(data);
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


const formatArray = (array) => {
  if (!Array.isArray(array)) {
    return '{}'; // Возвращаем пустой массив в формате PostgreSQL
  }
  return `{${array.map((item) => `"${item}"`).join(',')}}`;
};


router.post('/add/companies', upload.single('image'), async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token is missing or invalid' });
  }

  const token = authHeader.split(' ')[1];

  try {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Error verifying token:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }

      const userEmail = decoded.email;

      const {
        companyName,
        ownerName,
        email,
        phone,
        website,
        experience,
        services,
        description,
      } = req.body;

      const {
        selectedActions = '[]',
        selectedBuilds = '[]',
        selectedInstalls = '[]',
        selectedReplaces = '[]',
        selectedRemoves = '[]',
        selectedRepairs = '[]',
        selectedCleans = '[]',
        selectedAssembles = '[]',
        selectedObjects = '[]',
        selectedLocations = '[]',
        selectedSizes = '[]',
        selectedTimes = '[]',
      } = req.body;

      const formattedActions = formatArray(JSON.parse(selectedActions));
      const formattedBuilds = formatArray(JSON.parse(selectedBuilds));
      const formattedInstalls = formatArray(JSON.parse(selectedInstalls));
      const formattedReplaces = formatArray(JSON.parse(selectedReplaces));
      const formattedRemoves = formatArray(JSON.parse(selectedRemoves));
      const formattedRepairs = formatArray(JSON.parse(selectedRepairs));
      const formattedCleans = formatArray(JSON.parse(selectedCleans));
      const formattedAssembles = formatArray(JSON.parse(selectedAssembles));
      const formattedObjects = formatArray(JSON.parse(selectedObjects));
      const formattedLocations = formatArray(JSON.parse(selectedLocations));
      const formattedSizes = formatArray(JSON.parse(selectedSizes));
      const formattedTimes = formatArray(JSON.parse(selectedTimes));

      if (!companyName || !ownerName || !email || !phone || !experience || !services || !description) {
        return res.status(400).json({ message: 'All required fields must be filled' });
      }

      let imageUrl = null;

      if (req.file) {
        const fileName = `${Date.now()}-${req.file.originalname}`;
        const params = {
          Bucket: BUCKET_NAME,
          Key: fileName,
          Body: req.file.buffer,
          ContentType: req.file.mimetype,
          ACL: 'public-read',
        };

        try {
          const uploadResult = await s3.upload(params).promise();
          imageUrl = uploadResult.Location;
        } catch (uploadError) {
          console.error('Error uploading image to Vultr:', uploadError);
          return res.status(500).json({ message: 'Failed to upload image' });
        }
      }

      try {
        const { data: newContractor, error: insertError } = await supabase.from('companies').insert([
          {
            company_name: companyName,
            owner_name: ownerName,
            email,
            phone,
            website,
            years_in_business: experience,
            services,
            description,
            selected_actions: formattedActions,
            selected_builds: formattedBuilds,
            selected_installs: formattedInstalls,
            selected_replaces: formattedReplaces,
            selected_removes: formattedRemoves,
            selected_repairs: formattedRepairs,
            selected_cleans: formattedCleans,
            selected_assembles: formattedAssembles,
            selected_objects: formattedObjects,
            selected_locations: formattedLocations,
            selected_sizes: formattedSizes,
            selected_times: formattedTimes,
            user_email: userEmail,
            status: 'review',
            image_url: imageUrl,
          },
        ]).select().single();

        if (insertError) {
          console.error('Error inserting data:', insertError);
          return res.status(500).json({ message: 'Failed to save data' });
        }

        // Получаем обновлённый список контрактов текущего пользователя
        const { data: userContracts, error: fetchError } = await supabase
          .from('companies')
          .select('*')
          .eq('user_email', userEmail)
          .order('created_at', { ascending: false });

        if (fetchError) {
          console.error('Error fetching user contracts:', fetchError);
          return res.status(500).json({ message: 'Failed to fetch user contracts' });
        }

        res.status(201).json({ message: 'Company successfully added', contracts: userContracts });
      } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});



router.post('/applications', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token is missing or invalid' });
  }

  const token = authHeader.split(' ')[1];

  try {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }

      const userEmail = decoded.email; // Извлекаем email из токена

      const {
        companyName,
        ownerName,
        email,
        phone,
        website,
        experience,
        services,
        description,
      } = req.body;

      const {
        selectedActions = '[]',
        selectedObjects = '[]',
        selectedLocations = '[]',
        selectedSizes = '[]',
        selectedTimes = '[]',
      } = req.body;

      const formattedActions = formatArray(JSON.parse(selectedActions));
      const formattedObjects = formatArray(JSON.parse(selectedObjects));
      const formattedLocations = formatArray(JSON.parse(selectedLocations));
      const formattedSizes = formatArray(JSON.parse(selectedSizes));
      const formattedTimes = formatArray(JSON.parse(selectedTimes));

      // Проверка обязательных полей
      if (!companyName || !ownerName || !email || !phone || !experience || !services || !description) {
        return res.status(400).json({ message: 'All required fields must be filled' });
      }

      try {
        // Записываем данные в таблицу заявок
        const { data, error } = await supabase.from('consideration_companies').insert([
          {
            company_name: companyName,
            owner_name: ownerName,
            email,
            phone,
            website,
            experience: parseInt(experience, 10),
            services,
            description,
            status: 'pending',
            selected_actions: formattedActions,
            selected_objects: formattedObjects,
            selected_locations: formattedLocations,
            selected_sizes: formattedSizes,
            selected_times: formattedTimes,
            user_email: userEmail,
          },
        ]);

        if (error) {
          console.error('Error inserting application:', error);
          return res.status(500).json({ message: 'Failed to submit application' });
        }

        res.status(201).json({ message: 'Application submitted successfully', data });
      } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});


router.get('/companies/user', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Authorization header is missing or invalid');
    return res.status(401).json({ message: 'Authorization token is missing or invalid' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Асинхронная проверка токена
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Error verifying token:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }

      const userEmail = decoded.email; // Извлекаем email из токена

      // Получаем компании текущего пользователя
      const { data, error } = await supabase
        .from('companies') // Замените на вашу таблицу
        .select('*')
        .eq('user_email', userEmail) // Фильтруем по email пользователя
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error fetching user companies:', error);
        return res.status(500).json({ message: 'Failed to fetch user companies' });
      }
      console.log('User companies:', data);
      res.status(200).json(data);
    });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

router.get('/users/me', async (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // Проверяем токен
        jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
            if (err) {
                console.error('Error verifying token:', err);
                return res.status(401).json({ message: 'Invalid token' });
            }

            const userEmail = decoded.email; // Извлекаем email из токена
            const username = decoded.name || 'Anonymous'; // Извлекаем имя пользователя, если доступно
            const picture = decoded.picture || null; // Извлекаем изображение пользователя, если доступно

            // Проверяем, существует ли пользователь в базе данных
            const { data: existingUser, error: userError } = await supabase
                .from('users')
                .select('*')
                .eq('email', userEmail)
                .single();

            if (userError && userError.code !== 'PGRST116') {
                console.error('Error fetching user:', userError);
                return res.status(500).json({ message: 'Failed to fetch user' });
            }

            if (existingUser) {
                return res.status(200).json(existingUser);
            }

            // Если пользователь не найден, создаем нового
            const { data: newUser, error: newUserError } = await supabase
                .from('users')
                .insert([
                    {
                        email: userEmail,
                        username,
                        picture, // Сохраняем изображение
                        created_at: new Date().toISOString(),
                    },
                ])
                .single();

            if (newUserError) {
                console.error('Error creating user:', newUserError);
                return res.status(500).json({ message: 'Failed to create user' });
            }
            res.status(201).json(newUser);
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});


router.post('/chats', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('Authorization header is missing or invalid');
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }
  
      const userEmail = decoded.email;
      const { companyId } = req.body;
  
      try {
        // Получаем компанию по ID
        const { data: company, error: companyError } = await supabase
          .from('companies')
          .select('user_email')
          .eq('id', companyId)
          .single();
  
        if (companyError || !company) {
          console.error('Company not found:', companyError);
          return res.status(404).json({ message: 'Company not found' });
        }
  
        const contractorEmail = company.user_email;
  
        // Получаем user_id инициатора
        const { data: userA, error: errorA } = await supabase
          .from('users')
          .select('user_id')
          .eq('email', userEmail)
          .single();
  
        // Получаем user_id владельца компании
        const { data: userB, error: errorB } = await supabase
          .from('users')
          .select('user_id')
          .eq('email', contractorEmail)
          .single();
  
        if (errorA || errorB || !userA || !userB) {
          console.error('Error fetching users:', errorA || errorB);
          return res.status(404).json({ message: 'Users not found' });
        }
  
        const [userIdA, userIdB] = [userA.user_id, userB.user_id];
  
        // Проверяем, есть ли уже чат между ними
        const { data: existingChats, error: chatCheckError } = await supabase
          .rpc('find_existing_chat', { user_id_a: userIdA, user_id_b: userIdB });
  
        if (chatCheckError) {
          console.error('Error checking existing chats:', chatCheckError);
          return res.status(500).json({ message: 'Failed to check existing chats' });
        }
  
        if (existingChats.length > 0) {
          return res.status(200).json({ message: 'Chat already exists', chatId: existingChats[0].chat_id });
        }
  
        // Создаем новый чат
        const { data: chat, error: chatError } = await supabase
          .from('chats')
          .insert({ created_at: new Date().toISOString() })
          .select()
          .single();
  
        if (chatError) {
          console.error('Error creating chat:', chatError);
          return res.status(500).json({ message: 'Failed to create chat' });
        }
  
        // Добавляем участников
        const { error: participantsError } = await supabase
          .from('chat_participants')
          .insert([
            { chat_id: chat.chat_id, user_id: userIdA },
            { chat_id: chat.chat_id, user_id: userIdB },
          ]);
  
        if (participantsError) {
          console.error('Error adding chat participants:', participantsError);
          return res.status(500).json({ message: 'Failed to add chat participants' });
        }
  
        res.status(201).json({ message: 'Chat created', chatId: chat.chat_id });
  
      } catch (err) {
        console.error('Error in chat creation:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  });


router.post('/messages', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Authorization header is missing or invalid');
    return res.status(401).json({ message: 'Authorization token is missing or invalid' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err);
      return res.status(401).json({ message: 'Invalid token' });
    }

    const userEmail = decoded.email;
    const { chatId, text } = req.body;

    if (!chatId || !text) {
      console.error('chatId or text is missing in the request body');
      return res.status(400).json({ message: 'chatId and text are required' });
    }

    try {
      const { data: user, error: userError } = await supabase
        .from('users')
        .select('user_id')
        .eq('email', userEmail)
        .single();

      if (userError || !user) {
        console.error('User not found:', userError);
        return res.status(404).json({ message: 'User not found' });
      }

      const userId = user.user_id;

      const { data: message, error: messageError } = await supabase
        .from('messages')
        .insert({
          chat_id: chatId,
          sender_id: userId,
          message_text: text,
          sent_at: new Date().toISOString(),
          is_read: false,
        })
        .select()
        .single();

      if (messageError) {
        console.error('Error creating message:', messageError);
        return res.status(500).json({ message: 'Failed to send message' });
      }

      // Уведомляем участников чата через Socket.IO, кроме отправителя
      const io = req.app.get('io');
      io.to(chatId).emit('newMessage', {
        id: message.message_id,
        sender_id: userId,
        content: message.message_text,
        timestamp: message.sent_at,
        chatId,
      });

      res.status(201).json({ message: 'Message sent', data: message });
    } catch (err) {
      console.error('Error sending message:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
});
  

router.get('/messages/:chatId', async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization token is missing or invalid' });
  }

  const token = authHeader.split(' ')[1];
  const { chatId } = req.params;

  try {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }

      const userEmail = decoded.email;

      // Получаем user_id текущего пользователя
      const { data: user, error: userError } = await supabase
        .from('users')
        .select('user_id')
        .eq('email', userEmail)
        .single();

      if (userError || !user) {
        console.error('User not found:', userError);
        return res.status(404).json({ message: 'User not found' });
      }

      const userId = user.user_id;

      // Проверяем, участвует ли пользователь в чате
      const { data: participant, error: participantError } = await supabase
        .from('chat_participants')
        .select('*')
        .eq('chat_id', chatId)
        .eq('user_id', userId)
        .single();

      if (participantError || !participant) {
        console.error('User not in chat:', participantError);
        return res.status(403).json({ message: 'User not in this chat' });
      }

      // Помечаем все непрочитанные сообщения, отправленные другим пользователем, как прочитанные
      const { error: updateError } = await supabase
        .from('messages')
        .update({ is_read: true })
        .eq('chat_id', chatId)
        .neq('sender_id', userId) // Исключаем сообщения, отправленные текущим пользователем
        .eq('is_read', false); // Только непрочитанные сообщения

      if (updateError) {
        console.error('Error updating messages:', updateError);
        return res.status(500).json({ message: 'Failed to update messages' });
      }

      // Получаем все сообщения чата
      const { data: messages, error: messagesError } = await supabase
        .from('messages')
        .select('message_id, sender_id, message_text, sent_at, is_read')
        .eq('chat_id', chatId)
        .order('sent_at', { ascending: true });

      if (messagesError) {
        console.error('Error fetching messages:', messagesError);
        return res.status(500).json({ message: 'Failed to fetch messages' });
      }

      // Получаем данные отправителей сообщений
      const senderIds = [...new Set(messages.map((msg) => msg.sender_id))]; // Уникальные sender_id
      const { data: senders, error: sendersError } = await supabase
        .from('users')
        .select('user_id, username, picture')
        .in('user_id', senderIds);

      if (sendersError) {
        console.error('Error fetching senders:', sendersError);
        return res.status(500).json({ message: 'Failed to fetch senders' });
      }

      // Добавляем имя и изображение к каждому сообщению
      const enrichedMessages = messages.map((msg) => {
        const sender = senders.find((user) => user.user_id === msg.sender_id);
        return {
          ...msg,
          sender_name: sender?.username || 'Unknown',
          sender_picture: sender?.picture || null,
        };
      });

      res.status(200).json({ user_id: userId, messages: enrichedMessages });
    });
  } catch (err) {
    console.error('Unexpected error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

router.get('/chats', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }
  
      const userEmail = decoded.email;
  
      try {
        // Получаем user_id текущего пользователя
        const { data: user, error: userError } = await supabase
          .from('users')
          .select('user_id')
          .eq('email', userEmail)
          .single();
  
        if (userError || !user) {
          return res.status(404).json({ message: 'User not found' });
        }
  
        const userId = user.user_id;
  
        // Получаем chat_id всех чатов пользователя
        const { data: chatParticipants, error: participantError } = await supabase
          .from('chat_participants')
          .select('chat_id')
          .eq('user_id', userId);
  
        if (participantError) {
          console.error('Error fetching chat participants:', participantError);
          return res.status(500).json({ message: 'Failed to fetch chat participants' });
        }
  
        const chatIds = chatParticipants.map((p) => p.chat_id);
  
        if (chatIds.length === 0) {
          return res.status(200).json({ chats: [] });
        }
  
        // Получаем все чаты
        const { data: chats, error: chatError } = await supabase
          .from('chats')
          .select('chat_id, created_at')
          .in('chat_id', chatIds)
          .order('created_at', { ascending: false });
  
        if (chatError) {
          return res.status(500).json({ message: 'Failed to fetch chats' });
        }
  
        // Для каждого чата получаем второго участника, последнее сообщение и количество непрочитанных сообщений
        const enrichedChats = await Promise.all(
          chats.map(async (chat) => {
            const { data: participants, error: participantFetchError } = await supabase
              .from('chat_participants')
              .select('user_id')
              .eq('chat_id', chat.chat_id);
  
            if (participantFetchError || !participants) {
              console.error('Error fetching participants:', participantFetchError);
              return null;
            }
  
            const otherUser = participants.find((p) => p.user_id !== userId);
            if (!otherUser) {
              console.error('No other user found in chat:', chat.chat_id);
              return null;
            }
  
            const { data: userData, error: userFetchError } = await supabase
              .from('users')
              .select('username, picture')
              .eq('user_id', otherUser.user_id)
              .single();
  
            if (userFetchError || !userData) {
              console.error('Error fetching user data:', userFetchError);
              return null;
            }
  
            // Получаем последнее сообщение для чата
            const { data: lastMessage, error: lastMessageError } = await supabase
              .from('messages')
              .select('message_text, sent_at, is_read')
              .eq('chat_id', chat.chat_id)
              .order('sent_at', { ascending: false })
              .limit(1)
              .maybeSingle();
  
            if (lastMessageError) {
              console.error('Error fetching last message:', lastMessageError);
            }
  
            // Подсчитываем количество непрочитанных сообщений
            const { count: unreadCount, error: unreadError } = await supabase
              .from('messages')
              .select('*', { count: 'exact' })
              .eq('chat_id', chat.chat_id)
              .eq('is_read', false)
              .neq('sender_id', userId); // Исключаем сообщения, отправленные текущим пользователем
  
            if (unreadError) {
              console.error('Error fetching unread messages:', unreadError);
            }
  
            return {
              chat_id: chat.chat_id,
              created_at: chat.created_at,
              participant: {
                username: userData.username,
                picture: userData.picture,
              },
              last_message: lastMessage ? lastMessage.message_text : 'No messages yet',
              last_message_time: lastMessage ? lastMessage.sent_at : null,
              unread_count: unreadCount || 0, // Количество непрочитанных сообщений
            };
          })
        );
  
        const filteredChats = enrichedChats.filter((chat) => chat !== null);
  
        res.status(200).json({ chats: filteredChats });
      } catch (err) {
        console.error('Error getting enriched chats:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  });


  router.post('/admin/applications/:id', upload.single('image'), async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role'];
        if (role !== 'admin') {
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { id } = req.params;
        const updateData = req.body;
  
        let imageUrl = null;
  
        if (req.file) {
          const fileName = `${Date.now()}-${req.file.originalname}`;
          const params = {
            Bucket: BUCKET_NAME,
            Key: fileName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype,
            ACL: 'public-read',
          };
  
          try {
            const uploadResult = await s3.upload(params).promise();
            imageUrl = uploadResult.Location;
          } catch (uploadError) {
            console.error('Error uploading image:', uploadError);
            return res.status(500).json({ message: 'Failed to upload image' });
          }
        }
  
        if (imageUrl) {
          updateData.image_url = imageUrl;
        }
  
        try {
          const { data, error } = await supabase
            .from('companies')
            .update(updateData)
            .eq('id', id);
  
          if (error) {
            console.error('Error updating application:', error);
            return res.status(500).json({ message: 'Failed to update application' });
          }
  
          res.status(200).json({ message: 'Application updated successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
  
  
  
  router.get('/admin/companies', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('Authorization header is missing or invalid');
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ message: 'Invalid token' });
      }
  
      const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
      if (role !== 'admin') {
        console.error('Access denied: User is not an admin');
        return res.status(403).json({ message: 'Access denied' });
      }
  
      const { status } = req.query;
  
      try {
        let query = supabase.from('companies').select('*').order('created_at', { ascending: false });
  
        if (status === 'active') {
          query = query.eq('status', 'active');
        } else if (status === '!active') {
          query = query.neq('status', 'active');
        }
  
        const { data, error } = await query;
  
        if (error) {
          console.error('Error fetching companies:', error);
          return res.status(500).json({ message: 'Failed to fetch companies' });
        }
        
        res.status(200).json(data);
      } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
      }
    });
  });


  router.post('/admin/companies/:id', upload.single('image'), async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role'];
        if (role !== 'admin') {
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { id } = req.params;
        const updateData = req.body;
  
        let imageUrl = null;
  
        if (req.file) {
          const fileName = `${Date.now()}-${req.file.originalname}`;
          const params = {
            Bucket: BUCKET_NAME,
            Key: fileName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype,
            ACL: 'public-read',
          };
  
          try {
            const uploadResult = await s3.upload(params).promise();
            imageUrl = uploadResult.Location;
          } catch (uploadError) {
            console.error('Error uploading image:', uploadError);
            return res.status(500).json({ message: 'Failed to upload image' });
          }
        }
  
        if (imageUrl) {
          updateData.image_url = imageUrl;
        }
  
        try {
          const { data, error } = await supabase
            .from('companies')
            .update(updateData)
            .eq('id', id);
  
          if (error) {
            console.error('Error updating company:', error);
            return res.status(500).json({ message: 'Failed to update company' });
          }
  
          res.status(200).json({ message: 'Company updated successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });



  router.delete('/admin/companies/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
        if (role !== 'admin') {
          console.error('Access denied: User is not an admin');
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { id } = req.params;
  
        try {
          const { data, error } = await supabase
            .from('companies')
            .delete()
            .eq('id', id);
  
          if (error) {
            console.error('Error deleting company:', error);
            return res.status(500).json({ message: 'Failed to delete company' });
          }
  
          res.status(200).json({ message: 'Company deleted successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });


  router.post('/admin/companies/:id/activate', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
        if (role !== 'admin') {
          console.error('Access denied: User is not an admin');
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { id } = req.params;
  
        try {
          // Обновляем статус компании на "active"
          const { data, error } = await supabase
            .from('companies')
            .update({ status: 'active' })
            .eq('id', id);
  
          if (error) {
            console.error('Error updating company status:', error);
            return res.status(500).json({ message: 'Failed to update company status' });
          }
  
          res.status(200).json({ message: 'Company status updated to active', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });


  router.post('/admin/companies/:id/reject', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
        if (role !== 'admin') {
          console.error('Access denied: User is not an admin');
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { id } = req.params;
  
        try {
          // Обновляем статус компании на "rejected"
          const { data, error } = await supabase
            .from('companies')
            .update({ status: 'rejected' })
            .eq('id', id);
  
          if (error) {
            console.error('Error updating company status:', error);
            return res.status(500).json({ message: 'Failed to update company status' });
          }
  
          res.status(200).json({ message: 'Company status updated to rejected', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });


  


  router.post('/search-options', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
        if (role !== 'admin') {
          console.error('Access denied: User is not an admin');
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { category, value, next_category } = req.body;
  
        if (!category || !value) {
          return res.status(400).json({ message: 'Category and value are required' });
        }
  
        try {
          const { data, error } = await supabase
            .from('search_options')
            .insert([{ category, value, next_category }]);
  
          if (error) {
            console.error('Error adding search option:', error);
            return res.status(500).json({ message: 'Failed to add search option' });
          }
  
          res.status(201).json({ message: 'Search option added successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });


  router.delete('/search-options', async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }

        const role = decoded['https://Contractor.com/role']; // Извлекаем роль из токена
        if (role !== 'admin') {
          console.error('Access denied: User is not an admin');
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const { category, value } = req.body;
  
        if (!category || !value) {
          return res.status(400).json({ message: 'Category and value are required' });
        }
  
        try {
          const { data, error } = await supabase
            .from('search_options')
            .delete()
            .eq('category', category)
            .eq('value', value);
  
          if (error) {
            console.error('Error deleting search option:', error);
            return res.status(500).json({ message: 'Failed to delete search option' });
          }
  
          res.status(200).json({ message: 'Search option deleted successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });



  router.post('/admin/companies', upload.single('image'), async (req, res) => {
    const authHeader = req.headers.authorization;
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('Authorization header is missing or invalid');
      return res.status(401).json({ message: 'Authorization token is missing or invalid' });
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
        if (err) {
          console.error('Token verification error:', err);
          return res.status(401).json({ message: 'Invalid token' });
        }
  
        const role = decoded['https://Contractor.com/role'];
        if (role !== 'admin') {
          return res.status(403).json({ message: 'Access denied' });
        }
  
        const {
          company_name,
          owner_name,
          email,
          phone,
          website,
          services,
          description,
          rating,
          working_hours,
          years_in_business,
          verified,
          selected_actions,
          selected_builds,
          selected_installs,
          selected_replaces,
          selected_removes,
          selected_repairs,
          selected_cleans,
          selected_assembles,
          selected_objects,
          selected_locations,
          selected_sizes,
          selected_times,
          user_email,
        } = req.body;
  
        // Преобразуем данные в нужный формат
        const formattedRating = parseFloat(rating);
        const formattedYearsInBusiness = parseInt(years_in_business, 10);
        const formattedVerified = verified === 'true';
        const formattedActions = JSON.parse(selected_actions);
        const formattedBuilds = JSON.parse(selected_builds);
        const formattedInstalls = JSON.parse(selected_installs);
        const formattedReplaces = JSON.parse(selected_replaces);
        const formattedRemoves = JSON.parse(selected_removes);
        const formattedRepairs = JSON.parse(selected_repairs);
        const formattedCleans = JSON.parse(selected_cleans);
        const formattedAssembles = JSON.parse(selected_assembles);
        const formattedObjects = JSON.parse(selected_objects);
        const formattedLocations = JSON.parse(selected_locations);
        const formattedSizes = JSON.parse(selected_sizes);
        const formattedTimes = JSON.parse(selected_times);
  
        if (
          !company_name ||
          !owner_name ||
          !email ||
          !phone ||
          !services ||
          !description ||
          !user_email
        ) {
          console.error('Missing required fields in request body:', req.body);
          return res.status(400).json({ message: 'All required fields must be filled' });
        }
  
        let imageUrl = null;
  
        if (req.file) {
          const fileName = `${Date.now()}-${req.file.originalname}`;
          const params = {
            Bucket: BUCKET_NAME,
            Key: fileName,
            Body: req.file.buffer,
            ContentType: req.file.mimetype,
            ACL: 'public-read',
          };
  
          try {
            const uploadResult = await s3.upload(params).promise();
            imageUrl = uploadResult.Location;
          } catch (uploadError) {
            console.error('Error uploading image:', uploadError);
            return res.status(500).json({ message: 'Failed to upload image' });
          }
        }
  
        try {
          const { data, error } = await supabase.from('companies').insert([
            {
              company_name,
              owner_name,
              email,
              phone,
              website,
              services,
              description,
              rating: formattedRating,
              working_hours,
              years_in_business: formattedYearsInBusiness,
              verified: formattedVerified,
              selected_actions: formattedActions,
              selected_builds: formattedBuilds,
              selected_installs: formattedInstalls,
              selected_replaces: formattedReplaces,
              selected_removes: formattedRemoves,
              selected_repairs: formattedRepairs,
              selected_cleans: formattedCleans,
              selected_assembles: formattedAssembles,
              selected_objects: formattedObjects,
              selected_locations: formattedLocations,
              selected_sizes: formattedSizes,
              selected_times: formattedTimes,
              user_email,
              image_url: imageUrl,
              status: 'active',
            },
          ]);
  
          if (error) {
            console.error('Error inserting company:', error);
            return res.status(500).json({ message: 'Failed to add company' });
          }
  
          res.status(201).json({ message: 'Company added successfully', data });
        } catch (err) {
          console.error('Unexpected error:', err);
          res.status(500).json({ message: 'Internal Server Error' });
        }
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
  
module.exports = router;