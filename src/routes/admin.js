const express = require('express');
const router = express.Router();
const supabase = require('../db/connect');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const { s3, BUCKET_NAME } = require('../db/vultr');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

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

router.post('/applications/:id', upload.single('image'), async (req, res) => {
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



router.get('/companies', async (req, res) => {
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


router.post('/companies/:id', upload.single('image'), async (req, res) => {
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



router.delete('/companies/:id', async (req, res) => {
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


  router.post('/companies/:id/activate', async (req, res) => {
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

        try {
            // Получаем компанию и дату окончания подписки
            const { data: company, error: companyError } = await supabase
            .from('companies')
            .select('user_email, company_name, subscription_until')
            .eq('id', id)
            .single();

            if (companyError || !company) {
            return res.status(404).json({ message: 'Company not found' });
            }

            // Проверяем срок подписки
            const now = new Date();
            const until = company.subscription_until ? new Date(company.subscription_until) : null;
            let newStatus = 'payment';
            if (until && until > now) {
            newStatus = 'active';
            }

            // Обновляем статус
            const { data, error } = await supabase
            .from('companies')
            .update({ status: newStatus })
            .eq('id', id);

            if (error) {
            console.error('Error updating company status:', error);
            return res.status(500).json({ message: 'Failed to update company status' });
            }

            // Добавляем уведомление
            const notifType = newStatus === 'active' ? 'success' : 'warning';
            const notifMsg = newStatus === 'active'
            ? `Your company "${company.company_name}" has successfully passed moderation.`
            : `Your company "${company.company_name}" requires payment to activate.`;

            const { error: notifError } = await supabase.from('notifications').insert([{
            user_email: company.user_email,
            type: notifType,
            message: notifMsg,
            created_at: new Date().toISOString(),
            read: false
            }]);

            if (notifError) {
            console.error('Ошибка добавления уведомления:', notifError);
            }

            res.status(200).json({ message: `Company status updated to ${newStatus}`, data });
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



router.post('/companies/:id/reject', async (req, res) => {
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
  
          // Получаем компанию по id
          const { data: company, error: companyError } = await supabase
            .from('companies')
            .select('user_email, company_name')
            .eq('id', id)
            .single();
  
          if (companyError || !company) {
            return res.status(404).json({ message: 'Company not found' });
          }
  
          // Получаем user_id по user_email
          const { data: user, error: userError } = await supabase
            .from('users')
            .select('user_id')
            .eq('email', company.user_email)
            .single();
  
          if (userError || !user) {
            return res.status(404).json({ message: 'User not found' });
          }
  
          // Добавляем уведомление
          const { data: notifData, error: notifError } = await supabase.from('notifications').insert([{
            user_email: company.user_email,
            type: 'error',
            message: `Your Company "${company.company_name}" has been rejected.`,
            created_at: new Date().toISOString(),
            read: false
          }]);

          if (notifError) {
            console.error('Ошибка добавления уведомления:', notifError);
            return res.status(500).json({ message: 'Failed to add notification', notifError });
          } else {
            console.log('Уведомление успешно добавлено:', notifData);
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



  router.post('/companies', upload.single('image'), async (req, res) => {
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